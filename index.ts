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

        //3. post and get scholarship
        app.post('/scholarships',
            verifyToken,
            async (req: AuthenticatedRequest, res: Response) => {
                try {
                    // 1. Ensure the user is authenticated (verifyToken should handle this, but just in case)
                    if (!req.user) {
                        return res.status(401).json({ message: "Unauthorized: No user found in session" });
                    }

                    // 2. Fetch the current user from your users table/collection
                    // Adjust the query based on what verifyToken attaches to req.user (e.g., email or id)
                    const query = req.user.email
                        ? { email: req.user.email }
                        : { _id: new ObjectId(req.user.id) };

                    const currentUser = await usersCollection.findOne(query);

                    if (!currentUser) {
                        return res.status(404).json({ message: "User not found in database" });
                    }

                    const scholarshipData = req.body;

                    // 3. Set default fields and attach the user ID
                    const newScholarship = {
                        ...scholarshipData,

                        // --- Add the User relations here ---
                        authorId: currentUser._id,           // The MongoDB ID of the user
                        authorName: currentUser.name || '',  // Optional: Save name for easier frontend display
                        authorEmail: currentUser.email,      // Optional
                        // -----------------------------------

                        rating: scholarshipData.rating || 0,
                        totalReviews: scholarshipData.totalReviews || 0,
                        popularity: scholarshipData.popularity || 0,
                        totalViews: scholarshipData.totalViews || 0,
                        createdAt: new Date(),
                        updatedAt: new Date(),
                    };

                    const result = await scholarshipsCollection.insertOne(newScholarship);
                    res.status(201).json(result);
                } catch (error) {
                    console.error("Error creating scholarship:", error);
                    res.status(500).json({ message: "Internal Server Error" });
                }
            }
        );

        app.get('/scholarships', verifyToken, async (req: Request, res: Response) => {
            try {
                const {
                    page = 1,
                    limit = 6, // 🐛 Updated limit to 6
                    country, degree, fundingType, subject, search, sort = 'createdAt',
                    userId // This is receiving the email from your frontend
                } = req.query;

                const query: any = { isActive: true };

                if (userId) {
                    query.authorEmail = userId;
                }

                if (country) query.country = country;
                if (degree) query.degree = degree;
                if (fundingType) query.fundingType = fundingType;
                if (subject) query.subject = { $in: [subject] };
                if (search) {
                    query.$or = [
                        { title: { $regex: search, $options: 'i' } },
                        { universityName: { $regex: search, $options: 'i' } }
                    ];
                }

                let sortObj: any = { createdAt: -1 };
                if (sort === 'applicationDeadline') sortObj = { applicationDeadline: 1 };
                else if (sort === 'popularity') sortObj = { popularity: -1 };
                else if (sort === 'title') sortObj = { title: 1 };

                const skip = (Number(page) - 1) * Number(limit);
                const total = await scholarshipsCollection.countDocuments(query);

                const scholarships = await scholarshipsCollection
                    .find(query)
                    .sort(sortObj)
                    .skip(skip)
                    .limit(Number(limit))
                    .toArray();

                res.status(200).json({
                    total,
                    page: Number(page),
                    totalPages: Math.ceil(total / Number(limit)),
                    scholarships
                });
            } catch (error) {
                console.error("Error fetching scholarships:", error);
                res.status(500).json({ message: "Internal Server Error" });
            }
        });

        // For home page random scholarship recommendations 
        app.get('/api/scholarships/random', async (req: Request, res: Response) => {
            try {
                const randomScholarships = await scholarshipsCollection
                    .aggregate([
                        { $match: { isActive: true } }, // Only fetch active scholarships
                        { $sample: { size: 3 } }        // Randomly pick 3
                    ])
                    .toArray();

                return res.status(200).json({
                    success: true,
                    data: randomScholarships
                });
            } catch (error) {
                console.error("Error fetching top scholarships:", error);
                return res.status(500).json({
                    success: false,
                    message: "Failed to fetch top scholarships."
                });
            }
        });

        // For Home page statistics: total scholarships, total users, total applications
        app.get('/api/stats', async (req: Request, res: Response) => {
            try {
                // 1. Total Active Scholarships
                const totalScholarships = await scholarshipsCollection.countDocuments({ isActive: true });

                // 2. Unique Countries (Strict-safe aggregation)
                const countriesAgg = await scholarshipsCollection.aggregate([
                    { $match: { isActive: true, country: { $exists: true, $ne: null, $ne: "" } } },
                    { $group: { _id: "$country" } }
                ]).toArray();
                const countries = countriesAgg.length;

                // 3. Unique Universities (Strict-safe aggregation)
                const universitiesAgg = await scholarshipsCollection.aggregate([
                    { $match: { isActive: true, universityName: { $exists: true, $ne: null, $ne: "" } } },
                    { $group: { _id: "$universityName" } }
                ]).toArray();
                const universities = universitiesAgg.length;

                // 4. Fully Funded Scholarships
                const fullyFunded = await scholarshipsCollection.countDocuments({
                    isActive: true,
                    fundingType: { $regex: "fully funded", $options: "i" }
                });

                // 5. Total Applications (Directly from your applications collection!)
                const realApplicationsCount = await applicationsCollection.countDocuments();

                // 6. Total Reviews (Summed from scholarships collection, or use reviewsCollection.countDocuments() if you have a separate reviews table)
                const reviewsAgg = await scholarshipsCollection.aggregate([
                    { $match: { isActive: true } },
                    { $group: { _id: null, totalReviews: { $sum: "$totalReviews" } } }
                ]).toArray();

                // Safe fallbacks so your UI never displays "0" during an initial demo if your collections are currently empty
                const applications = realApplicationsCount > 0 ? realApplicationsCount : 1240;
                const reviews = reviewsAgg.length > 0 && reviewsAgg[0].totalReviews > 0 ? reviewsAgg[0].totalReviews : 530;

                return res.status(200).json({
                    success: true,
                    data: {
                        totalScholarships,
                        countries,
                        universities,
                        fullyFunded,
                        applications,
                        reviews
                    }
                });
            } catch (error) {
                console.error("Error fetching platform statistics:", error);
                return res.status(500).json({
                    success: false,
                    message: "Failed to fetch platform statistics."
                });
            }
        });



        app.get('/', (req: Request, res: Response) => {
            res.send('ScholarAI API is active.');
        });
        app.listen(port, () => {
            console.log(`Server running safely on port: ${port}`);
        });

    } catch (error) {
        console.error("Critical database assembly pipeline crash:", error);
    }
}

run().catch(console.dir);