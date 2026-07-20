import express, { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { MongoClient, ServerApiVersion, ObjectId, Db } from 'mongodb';
import { createRemoteJWKSet, jwtVerify, JWTPayload } from 'jose-cjs';
import Groq from 'groq-sdk'; // <--- ADD THIS

dotenv.config();

const uri = process.env.MONGODB_URI;
const port = process.env.MONGODB_PORT || 5000;

if (!uri) {
    console.error("Critical Error: MONGODB_URI environment variable is missing.");
    process.exit(1);
}

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use(cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "Cookie"],
    exposedHeaders: ["Set-Cookie"]
}));

interface CustomJWTPayload extends JWTPayload {
    sub: string;
    id?: string;
    role?: string;
    isBlocked?: boolean;
}

export interface AuthenticatedRequest extends Request {
    user?: CustomJWTPayload;
}

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: false,
        deprecationErrors: true
    }
});

const JWKS = createRemoteJWKSet(new URL(`${process.env.CLIENT_URL}/api/auth/jwks`));
const groq = new Groq({
    apiKey: process.env.GROQ_API_KEY,
});

const verifyToken = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (req.method === 'OPTIONS') return next();

    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith("Bearer ")
        ? authHeader.split(" ")[1]
        : req.cookies?.["better-auth.session_token"];

    if (!token) {
        return res.status(401).json({ message: "Unauthorized: Missing Token" });
    }

    try {
        const { payload } = await jwtVerify(token, JWKS);
        const userId = payload.sub;

        if (!userId) {
            return res.status(401).json({ message: "Invalid token payload." });
        }

        const db = client.db("scholarai");
        const user = await db.collection("user").findOne({
            _id: ObjectId.isValid(userId) ? new ObjectId(userId) : userId
        });

        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        if (user.isBlocked) {
            return res.status(403).json({ message: "Your account has been blocked by the administrator." });
        }

        req.user = {
            ...(payload as CustomJWTPayload),
            id: payload.sub,
            role: user.role,
            isBlocked: user.isBlocked
        } as any;

        next();
    } catch (error: any) {
        return res.status(403).json({ message: "Forbidden: Invalid Token" });
    }
};
// Middleware for routes that guests CAN view, but logged-in users get extra data
const optionalVerifyToken = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (req.method === 'OPTIONS') return next();

    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith("Bearer ")
        ? authHeader.split(" ")[1]
        : req.cookies?.["better-auth.session_token"];

    if (!token) return next(); // Let guests pass

    try {
        const { payload } = await jwtVerify(token, JWKS);
        req.user = { id: payload.sub } as CustomJWTPayload;
    } catch (error) {
        // Token invalid/expired? Ignore and let them view as a guest
    }
    next();
};
async function run() {
    try {
        // await client.connect();
        const db: Db = client.db("scholarai");
        console.log("Database initialized. Collections ready.");

        const scholarshipsCollection = db.collection("scholarships");
        const reviewsCollection = db.collection("scholarship_reviews");
        const savedCollection = db.collection("saved_scholarships");
        const applicationsCollection = db.collection("applications");
        const usersCollection = db.collection('user');

        // ==========================================
        // 1. AI ASSISTANT API
        // ==========================================

        app.post('/ai/chat', async (req: Request, res: Response) => {
            try {
                const { messages } = req.body;

                if (!messages || !Array.isArray(messages)) {
                    return res.status(400).json({ message: "Invalid request: 'messages' array required" });
                }

                const completion = await groq.chat.completions.create({
                    model: "llama-3.3-70b-versatile",
                    messages: [
                        {
                            role: "system",
                            content: "You are ScholarAI Assistant. Help users with scholarships, universities, admissions, funding, SOPs, IELTS and study abroad. Keep responses concise.",
                        },
                        ...messages.map((msg: any) => ({
                            role: msg.role,
                            content: msg.content
                        }))
                    ],
                });

                res.json({
                    reply: completion.choices[0].message.content,
                });
            } catch (error) {
                console.error("AI Chat Error:", error);
                res.status(500).json({
                    message: "AI Error: Failed to generate response",
                });
            }
        });
        // 2. api recommendations engine
        app.get('/api/filters', async (req: Request, res: Response) => {
            try {
                // Strict-safe aggregation helpers replacing .distinct()
                const getUniqueFieldValues = async (fieldName: string) => {
                    return await scholarshipsCollection.aggregate([
                        { $match: { isActive: true } },
                        { $group: { _id: `$${fieldName}` } },
                        { $match: { _id: { $ne: null } } } // Strip out empty/null fields
                    ]).toArray();
                };

                const rawCountries = await getUniqueFieldValues("country");
                const rawDegrees = await getUniqueFieldValues("degree");
                const rawFundingTypes = await getUniqueFieldValues("fundingType");
                const rawSubjectsData = await scholarshipsCollection.aggregate([
                    { $match: { isActive: true } },
                    { $unwind: "$subject" }, // Unroll subject string arrays safely 
                    { $group: { _id: "$subject" } }
                ]).toArray();

                // Standardize output formats into plain string arrays for the front-end
                const countries = rawCountries.map(c => c._id).sort();
                const degrees = rawDegrees.map(d => d._id).sort();
                const fundingTypes = rawFundingTypes.map(f => f._id).sort();
                const subjects = rawSubjectsData.map(s => s._id).sort();

                res.json({ countries, degrees, fundingTypes, subjects });
            } catch (error) {
                console.error("Strict API filter lookup error:", error);
                res.status(500).json({ message: "Internal Server Error" });
            }
        });
        app.post('/api/ai/recommend', async (req: Request, res: Response) => {
            try {
                const { country, degree, subject, fundingType } = req.body;

                // 1. Build Query targeting exact MongoDB structure
                const query: any = { isActive: true };

                if (country) query.country = { $regex: country, $options: "i" };
                if (degree) query.degree = { $regex: degree, $options: "i" };
                if (fundingType) query.fundingType = { $regex: fundingType, $options: "i" };

                // CRITERIA 4: Using explicit array parsing logic for fields saved as collections
                if (subject) {
                    query.subject = { $in: [new RegExp(subject, "i")] };
                }

                // 2. Query MongoDB with a clean layout limit
                const scholarships = await scholarshipsCollection.find(query).limit(5).toArray();

                // CRITERIA 6 & 7: Plaintext string mapping containing vital target Application URLs
                const scholarshipList = scholarships.map((s: any) => `
        Title: ${s.title}
        University: ${s.universityName}
        Country: ${s.country}
        Degree Level: ${s.degree}
        Funding Profile: ${s.fundingType}
        Subjects Covered: ${Array.isArray(s.subject) ? s.subject.join(", ") : s.subject}
        Deadline: ${s.applicationDeadline || "N/A"}
        Application URL: ${s.applicationUrl || "N/A"}
        `).join("\n---");

                // CRITERIA 8: Rigorous algorithmic grading directive context
                const userPromptContext = `
        The user is currently searching for a scholarship with these criteria:
        - Target Country: ${country || "Any"}
        - Degree level: ${degree || "Any"}
        - Field of Study: ${subject || "Any"}
        - Funding Configuration: ${fundingType || "Any"}

        Here is a list of real matched records extracted from our system database:
        ${scholarshipList || "NO SCHOLARSHIPS FOUND IN SYSTEM DATABASE."}

        YOUR INSTRUCTIONS:
        1. If records are available above, choose the best three entries and rank them using this explicit criteria weight:
           - Priority 1: Country match
           - Priority 2: Degree level match
           - Priority 3: Subject field match
           - Priority 4: Funding type match
        
        2. For each recommended scholarship, present the Title, University, Application URL, and a clear bulleted "Why?" summary breaking down why it fits their search parameters perfectly.
        
        3. If the provided database record list is completely empty, kindly inform the user that no specific entries match their layout filters. Then, suggest 3 highly actionable, general steps they can take next to adjust their options.

        Deliver the advice directly. Do not reference structural terms like "based on the list provided above" or "our database" to the end user.
        `;

                // CRITERIA 5: Recommended Chat Completion format pairing System and User messages
                const completion = await groq.chat.completions.create({
                    model: "llama-3.3-70b-versatile",
                    messages: [
                        {
                            role: "system",
                            content: "You are ScholarAI, an expert scholarship advisor. Help users review options cleanly using simple markdown formats."
                        },
                        {
                            role: "user",
                            content: userPromptContext
                        }
                    ],
                });

                res.json({ recommendations: completion.choices[0].message.content });

            } catch (error) {
                console.error("AI Recommendation Engine Error:", error);
                res.status(500).json({ message: "Failed to generate system recommendations" });
            }
        });



        app.listen(port, () => {
            console.log(`Server running safely on port: ${port}`);
        });

    } catch (error) {
        console.error("Critical database assembly pipeline crash:", error);
    }
}

run().catch(console.dir);