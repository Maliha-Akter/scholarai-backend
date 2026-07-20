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
        // 2. AI ASSISTANT API
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

        

        app.listen(port, () => {
            console.log(`Server running safely on port: ${port}`);
        });

    } catch (error) {
        console.error("Critical database assembly pipeline crash:", error);
    }
}

run().catch(console.dir);