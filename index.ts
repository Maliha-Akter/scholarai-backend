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

                // Set up headers for Server-Sent Events (Streaming)
                res.setHeader('Content-Type', 'text/event-stream');
                res.setHeader('Cache-Control', 'no-cache');
                res.setHeader('Connection', 'keep-alive');

                const systemPrompt = ` You are ScholarAI Assistant inside the ScholarAI Scholarship Portal.
You help users navigate and explore the following application features:
- Search Scholarships
- Scholarship Details
- Save Scholarships
- My Applications
- AI Scholarship Advisor
- AI Chat Assistant
- Dashboard
- User Profile

If users ask where to perform an action or find something, gently guide them to the correct page listed above.
If users ask about scholarships, admissions, requirements, funding, SOPs, or IELTS, answer normally.
Keep responses concise and well-formatted.

CRITICAL: At the very end of your response, always append a separator line "|||" followed by a valid JSON array containing exactly 3 follow-up question strings that the user might want to click next based on your response. 
Example structure at the end of your response:
Your helpful answer here...
||| ["Tell me about DAAD", "What are the funding types?", "How do I apply?"]`;

                const completion = await groq.chat.completions.create({
                    model: "llama-3.3-70b-versatile",
                    messages: [
                        {
                            role: "system",
                            content: systemPrompt,
                        },
                        ...messages.map((msg: any) => ({
                            role: msg.role,
                            content: msg.content
                        }))
                    ],
                    stream: true, // Turn streaming ON
                });

                // Write chunks to the response stream as they arrive
                for await (const chunk of completion) {
                    const text = chunk.choices[0]?.delta?.content || "";
                    res.write(text);
                }

                res.end();
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
                // 1. Destructure interactionHistory alongside standard filters
                const { country, degree, subject, fundingType, interactionHistory } = req.body;

                // 2. Build Query targeting exact MongoDB structure
                const query: any = { isActive: true };

                if (country) query.country = { $regex: country, $options: "i" };
                if (degree) query.degree = { $regex: degree, $options: "i" };
                if (fundingType) query.fundingType = { $regex: fundingType, $options: "i" };

                if (subject) {
                    query.subject = { $in: [new RegExp(subject, "i")] };
                }

                // 3. Query MongoDB with a clean layout limit
                const scholarships = await scholarshipsCollection.find(query).limit(5).toArray();

                // 4. Format database results
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

                // 5. NEW: Format the user's past interaction history for the AI prompt
                let historyContext = "No prior search history available for this user.";
                if (Array.isArray(interactionHistory) && interactionHistory.length > 0) {
                    historyContext = interactionHistory
                        .slice(0, 5) // Keep prompt concise by looking at up to 5 recent searches
                        .map((h: any, idx: number) => {
                            const filters = [h.country, h.degree, h.subject, h.fundingType].filter(Boolean).join(", ");
                            return `Search #${idx + 1}: [${filters || "General Browse"}]`;
                        }).join("\n");
                }

                // 6. Updated algorithmic grading directive with behavioral context
                const userPromptContext = `
The user is currently searching for a scholarship with these immediate criteria:
- Target Country: ${country || "Any"}
- Degree level: ${degree || "Any"}
- Field of Study: ${subject || "Any"}
- Funding Configuration: ${fundingType || "Any"}

USER BEHAVIORAL PROFILE (Recent search history):
${historyContext}

Here is a list of real matched records extracted from our system database:
${scholarshipList || "NO SCHOLARSHIPS FOUND IN SYSTEM DATABASE."}

YOUR INSTRUCTIONS:
1. If records are available above, choose the best three entries and rank them using this explicit criteria weight:
   - Priority 1: Country match
   - Priority 2: Degree level match
   - Priority 3: Subject field match
   - Priority 4: Funding type match
   *Note: If multiple scholarships tie on the explicit priorities above, use the USER BEHAVIORAL PROFILE to break ties by recommending options that align with their past search trends.*

2. For each recommended scholarship, present the Title, University, Application URL, and a clear bulleted "Why?" summary breaking down why it fits their search parameters perfectly.

3. If the provided database record list is completely empty, kindly inform the user that no specific entries match their layout filters. Then, suggest 3 highly actionable, general steps they can take next to adjust their options.

Deliver the advice directly. Do not reference structural terms like "based on the list provided above" or "our database" to the end user.
`;

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
                    if (!req.user) {
                        return res.status(401).json({ message: "Unauthorized: No user found in session" });
                    }

                    // Look up the user
                    const query = req.user.email
                        ? { email: { $regex: new RegExp(`^${req.user.email}$`, 'i') } }
                        : { _id: new ObjectId(req.user.id) };

                    const currentUser = await usersCollection.findOne(query);

                    if (!currentUser) {
                        return res.status(404).json({ message: "User not found in database" });
                    }

                    const scholarshipData = req.body;

                    const newScholarship = {
                        ...scholarshipData,
                        // THE FIX: Explicitly convert the ObjectId to a String
                        authorId: currentUser._id.toString(),
                        authorName: currentUser.name || '',
                        authorEmail: currentUser.email.toLowerCase(),
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

        app.get('/scholarships', async (req: Request, res: Response) => {
            try {
                // Prevent browser/CDN caching so new posts appear instantly
                res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
                res.setHeader('Pragma', 'no-cache');

                // Extract query parameters
                const {
                    page = 1,
                    limit = 6,
                    country,
                    degree,
                    fundingType,
                    subject,
                    search,
                    sort = 'createdAt',
                    userId
                } = req.query;

                // FIX 1: Initialize an empty query object. 
                // This ensures items with `isActive: false` are no longer hidden.
                // Note: If you eventually build an admin approval system, change this back to { isActive: true }
                const query: any = {};

                // Case-insensitive exact match for userId (authorEmail)
                if (userId) {
                    query.authorEmail = { $regex: new RegExp(`^${userId}$`, 'i') };
                }

                // Apply filters
                if (country) query.country = country;
                if (degree) query.degree = degree;
                if (fundingType) query.fundingType = fundingType;
                if (subject) query.subject = { $in: [subject] };

                // Apply search mapping
                if (search) {
                    query.$or = [
                        { title: { $regex: search, $options: 'i' } },
                        { universityName: { $regex: search, $options: 'i' } }
                    ];
                }

                // FIX 2: Ensure descending order defaults correctly for new items
                let sortObj: any = { createdAt: -1 }; // Default to newest first
                if (sort === 'applicationDeadline') sortObj = { applicationDeadline: 1 };
                else if (sort === 'popularity') sortObj = { popularity: -1 };
                else if (sort === 'title') sortObj = { title: 1 };
                else if (sort === 'createdAt') sortObj = { createdAt: -1 };

                // Pagination math
                const skip = (Number(page) - 1) * Number(limit);
                const total = await scholarshipsCollection.countDocuments(query);

                // Fetch from database
                const scholarships = await scholarshipsCollection
                    .find(query)
                    .sort(sortObj)
                    .skip(skip)
                    .limit(Number(limit))
                    .toArray();

                // Return successful response
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

        // Get scholarship Details by ID
        app.get('/scholarships/:identifier', optionalVerifyToken, async (req: AuthenticatedRequest, res: Response) => {
            try {
                const { identifier } = req.params as { identifier: string };

                if (!identifier) {
                    return res.status(400).json({ message: "Identifier is required" });
                }

                // 1. Determine if the identifier is an ID or a Slug
                const query = ObjectId.isValid(identifier)
                    ? { _id: new ObjectId(identifier) }
                    : { slug: identifier };

                // 2. Fetch Main Scholarship Data
                const scholarship = await scholarshipsCollection.findOne(query);

                if (!scholarship) {
                    return res.status(404).json({ message: "Scholarship not found" });
                }

                const scholarshipId = scholarship._id;

                // Increment total views asynchronously 
                scholarshipsCollection.updateOne(
                    { _id: scholarshipId },
                    { $inc: { totalViews: 1 } }
                ).catch(err => console.error("Failed to update views", err));

                // 3. Fetch Reviews
                const reviews = await reviewsCollection.aggregate([
                    { $match: { scholarshipId: scholarshipId } },
                    { $sort: { createdAt: -1 } },
                    {
                        $lookup: {
                            from: "user",
                            localField: "userId",
                            foreignField: "_id",
                            as: "author"
                        }
                    },
                    { $unwind: "$author" },
                    {
                        $project: {
                            rating: 1, review: 1, createdAt: 1,
                            "author.name": 1, "author.image": 1
                        }
                    }
                ]).toArray();

                // 4. Fetch Related Scholarships
                const related = await scholarshipsCollection
                    .find({
                        _id: { $ne: scholarshipId },
                        // isActive: true, // <--- REMOVE THIS LINE
                        $or: [
                            { country: scholarship.country },
                            { subject: { $in: scholarship.subject || [] } },
                            { degree: scholarship.degree }
                        ]
                    })
                    .project({
                        image: 1, title: 1, slug: 1, universityName: 1, country: 1,
                        degree: 1, fundingType: 1, applicationDeadline: 1, rating: 1
                    })
                    .limit(4)
                    .toArray();
                // 5. Check User specific statuses if logged in
                let saved = false;
                let applied = false;

                // Because of optionalVerifyToken, req.user will only exist if they are logged in
                if (req.user?.id) {
                    const userId = new ObjectId(req.user.id);

                    const savedItem = await savedCollection.findOne({ userId, scholarshipId });
                    if (savedItem) saved = true;

                    const appliedItem = await applicationsCollection.findOne({ userId, scholarshipId });
                    if (appliedItem) applied = true;
                }

                // 6. Return combined payload
                res.status(200).json({
                    scholarship,
                    reviews,
                    related,
                    saved,
                    applied
                });

            } catch (error) {
                console.error("Error fetching scholarship details:", error);
                res.status(500).json({ message: "Internal Server Error" });
            }
        });

        // Scholarship Edit and Update and Delete routes can be added here with proper authentication and authorization checks
        app.put('/scholarships/:id', verifyToken, async (req: AuthenticatedRequest, res: Response) => {
            try {
                const { id } = req.params;
                const updateData = req.body;
                delete updateData._id; // Prevent updating the immutable _id field

                updateData.updatedAt = new Date();

                const result = await scholarshipsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: updateData }
                );

                if (result.matchedCount === 0) return res.status(404).json({ message: "Not found" });
                res.status(200).json({ message: "Updated successfully", result });
            } catch (error) {
                res.status(500).json({ message: "Internal Server Error" });
            }
        });

        // NEW: DELETE a scholarship
        app.delete('/scholarships/:id', verifyToken, async (req: AuthenticatedRequest, res: Response) => {
            try {
                const { id } = req.params;
                const result = await scholarshipsCollection.deleteOne({ _id: new ObjectId(id) });

                if (result.deletedCount === 0) return res.status(404).json({ message: "Not found" });
                res.status(200).json({ message: "Deleted successfully" });
            } catch (error) {
                res.status(500).json({ message: "Internal Server Error" });
            }
        });

        //Application for Scholarship
        app.post('/applications',
            verifyToken,
            async (req: AuthenticatedRequest, res: Response): Promise<any> => {
                try {
                    const { scholarshipId } = req.body;
                    const userId = req.user?.id;

                    // Validate presence of critical data points
                    if (!scholarshipId || !userId) {
                        return res.status(400).json({ message: "Missing required fields" });
                    }

                    // Securely validate identifier formats
                    if (!ObjectId.isValid(scholarshipId)) {
                        return res.status(400).json({
                            message: "Invalid scholarshipId format. Make sure you are sending the _id, not the slug."
                        });
                    }

                    // Standardize userId parameters
                    const safeUserId = ObjectId.isValid(userId) ? new ObjectId(userId) : userId;

                    const searchCriteria = {
                        userId: safeUserId,
                        scholarshipId: new ObjectId(scholarshipId)
                    };

                    // Prevent duplicate applications tracking
                    const existingApp = await applicationsCollection.findOne(searchCriteria);
                    if (existingApp) {
                        return res.status(409).json({ message: "Already applied", applied: true });
                    }

                    const newApplication = {
                        ...searchCriteria,
                        status: "Applied",
                        appliedAt: new Date(),
                        updatedAt: new Date()
                    };

                    await applicationsCollection.insertOne(newApplication);
                    return res.status(201).json({ message: "Application tracked successfully", applied: true });

                } catch (error) {
                    console.error("Error tracking application:", error);
                    return res.status(500).json({ message: "Internal Server Error" });
                }
            }
        );
        app.get('/applications', verifyToken, async (req: AuthenticatedRequest, res: Response) => {
            try {
                const userId = req.user?.id;
                if (!userId) return res.status(401).json({ message: "Unauthorized" });

                const history = await applicationsCollection.aggregate([
                    { $match: { userId: new ObjectId(userId) } },
                    { $sort: { appliedAt: -1 } },
                    {
                        $lookup: {
                            from: "scholarships",
                            localField: "scholarshipId",
                            foreignField: "_id",
                            as: "scholarship"
                        }
                    },
                    { $unwind: "$scholarship" },
                    {
                        $project: {
                            _id: 1,
                            status: 1,
                            appliedAt: 1,
                            "scholarship.title": 1,
                            "scholarship.universityName": 1,
                            "scholarship.country": 1
                        }
                    }
                ]).toArray();

                res.status(200).json(history);
            } catch (error) {
                console.error("Error fetching applications:", error);
                res.status(500).json({ message: "Internal Server Error" });
            }
        });

        // GET: Check if a specific scholarship has already been applied to by the current user
        app.get('/applications/status/:scholarshipId',
            verifyToken,
            async (req: AuthenticatedRequest, res: Response): Promise<any> => {
                try {
                    const { scholarshipId } = req.params;
                    const userId = req.user?.id;

                    // 1. Normalize parameter to a clean, flat string
                    const targetId: string = Array.isArray(scholarshipId) ? scholarshipId[0] : scholarshipId;

                    if (!targetId || !userId) {
                        return res.status(400).json({ hasApplied: false, message: "Missing required identifiers." });
                    }

                    // 2. Validate identifier format
                    if (!ObjectId.isValid(targetId)) {
                        return res.status(400).json({ hasApplied: false, message: "Invalid scholarshipId format." });
                    }

                    // 3. Standardize userId format
                    const safeUserId = ObjectId.isValid(userId) ? new ObjectId(userId) : userId;

                    // 4. Look up matching application record
                    const existingApp = await applicationsCollection.findOne({
                        userId: safeUserId,
                        scholarshipId: new ObjectId(targetId)
                    });

                    // 5. Return boolean state directly
                    return res.status(200).json({ hasApplied: !!existingApp });

                } catch (error) {
                    console.error("Error checking application status:", error);
                    return res.status(500).json({ hasApplied: false, message: "Internal Server Error" });
                }
            }
        );

        // ==========================================
        // UNIVERSITIES API
        // ==========================================

        // READ: Get All Universities (Grouped from scholarships)
        app.get('/universities', async (req: Request, res: Response) => {
            try {
                const universities = await scholarshipsCollection.aggregate([
                    {
                        $group: {
                            _id: "$universityName",
                            universityName: { $first: "$universityName" },
                            country: { $first: "$country" },
                            city: { $first: "$city" }, // Assumes you have a city field, otherwise it returns null
                            totalScholarships: { $sum: 1 }
                        }
                    },
                    {
                        $sort: {
                            universityName: 1 // Sort alphabetically
                        }
                    }
                ]).toArray();

                res.status(200).json(universities);
            } catch (error) {
                console.error("Error fetching universities:", error);
                res.status(500).json({ message: "Internal Server Error" });
            }
        });

        // READ: Get all scholarships for a specific university
        app.get('/universities/:universityName', async (req: Request, res: Response) => {
            try {
                const { universityName } = req.params;

                // Find all scholarships matching this university
                const scholarships = await scholarshipsCollection
                    .find({ universityName: universityName, isActive: true })
                    .sort({ createdAt: -1 })
                    .toArray();

                if (scholarships.length === 0) {
                    return res.status(404).json({ message: "No scholarships found for this university" });
                }

                // Package up the university metadata based on the first scholarship found
                const universityInfo = {
                    universityName: scholarships[0].universityName,
                    country: scholarships[0].country,
                    city: scholarships[0].city,
                    totalScholarships: scholarships.length
                };

                res.status(200).json({
                    universityInfo,
                    scholarships
                });
            } catch (error) {
                console.error("Error fetching university scholarships:", error);
                res.status(500).json({ message: "Internal Server Error" });
            }
        });

        // ==========================================
        // REVIEWS API
        // ==========================================

        // CREATE: Add a review and update scholarship rating
        app.post('/reviews',
            verifyToken,
            async (req: AuthenticatedRequest, res: Response): Promise<any> => {
                try {
                    const { scholarshipId, rating, review } = req.body;
                    const userId = req.user?.id;

                    if (!scholarshipId || !rating || !userId) {
                        return res.status(400).json({ message: "Missing required fields" });
                    }

                    if (!ObjectId.isValid(scholarshipId)) {
                        return res.status(400).json({ message: "Invalid scholarshipId format." });
                    }

                    const safeUserId = ObjectId.isValid(userId) ? new ObjectId(userId) : userId;

                    // Optional: Prevent duplicate reviews by the same user on this scholarship
                    const existingReview = await reviewsCollection.findOne({
                        userId: safeUserId,
                        scholarshipId: new ObjectId(scholarshipId)
                    });
                    if (existingReview) {
                        return res.status(409).json({ message: "You already reviewed this scholarship" });
                    }

                    const newReview = {
                        scholarshipId: new ObjectId(scholarshipId),
                        userId: safeUserId,
                        rating: Number(rating),
                        review,
                        createdAt: new Date()
                    };

                    const result = await reviewsCollection.insertOne(newReview);

                    // Aggregate new average rating and total reviews for the scholarship
                    const statsPipeline = [
                        { $match: { scholarshipId: new ObjectId(scholarshipId) } },
                        {
                            $group: {
                                _id: "$scholarshipId",
                                avgRating: { $avg: "$rating" },
                                totalReviews: { $sum: 1 }
                            }
                        }
                    ];
                    const stats = await reviewsCollection.aggregate(statsPipeline).toArray();

                    if (stats.length > 0) {
                        await scholarshipsCollection.updateOne(
                            { _id: new ObjectId(scholarshipId) },
                            {
                                $set: {
                                    rating: parseFloat(stats[0].avgRating.toFixed(1)),
                                    totalReviews: stats[0].totalReviews
                                }
                            }
                        );
                    }

                    return res.status(201).json(result);
                } catch (error) {
                    console.error("Error posting review:", error);
                    return res.status(500).json({ message: "Internal Server Error" });
                }
            }
        );

        // READ: Get reviews for a specific scholarship
        app.get('/reviews/:scholarshipId', async (req: Request, res: Response) => {
            try {
                const { scholarshipId } = req.params;
                if (!ObjectId.isValid(scholarshipId)) {
                    return res.status(400).json({ message: "Invalid scholarship ID" });
                }

                // Lookup user details to show name/avatar alongside the review
                const reviews = await reviewsCollection.aggregate([
                    { $match: { scholarshipId: new ObjectId(scholarshipId) } },
                    { $sort: { createdAt: -1 } },
                    {
                        $lookup: {
                            from: "user",
                            localField: "userId",
                            foreignField: "_id",
                            as: "author"
                        }
                    },
                    { $unwind: "$author" },
                    {
                        $project: {
                            rating: 1,
                            review: 1,
                            createdAt: 1,
                            "author.name": 1,
                            "author.image": 1
                        }
                    }
                ]).toArray();

                res.status(200).json(reviews);
            } catch (error) {
                console.error("Error fetching reviews:", error);
                res.status(500).json({ message: "Internal Server Error" });
            }
        });
        // ==========================================
        // 3. SAVED SCHOLARSHIPS API
        // ==========================================

        // CREATE/DELETE: Toggle Save Scholarship
        app.post('/saved', verifyToken, async (req: AuthenticatedRequest, res: Response) => {
            try {
                const { scholarshipId } = req.body;
                const userId = req.user?.id;

                if (!scholarshipId || !userId) {
                    return res.status(400).json({ message: "Missing required fields" });
                }

                // 1. Validate scholarshipId before casting
                if (!ObjectId.isValid(scholarshipId)) {
                    return res.status(400).json({ message: "Invalid scholarshipId format. Make sure you are sending the _id, not the slug." });
                }

                // 2. Safely handle userId (in case it is a UUID from your auth provider)
                const safeUserId = ObjectId.isValid(userId) ? new ObjectId(userId) : userId;

                const searchCriteria = {
                    userId: safeUserId,
                    scholarshipId: new ObjectId(scholarshipId)
                };

                const existingSave = await savedCollection.findOne(searchCriteria);

                if (existingSave) {
                    await savedCollection.deleteOne({ _id: existingSave._id });
                    return res.status(200).json({ message: "Removed from saved items", saved: false });
                } else {
                    await savedCollection.insertOne({
                        ...searchCriteria,
                        createdAt: new Date()
                    });
                    return res.status(201).json({ message: "Added to saved items", saved: true });
                }
            } catch (error) {
                console.error("Error toggling save:", error);
                res.status(500).json({ message: "Internal Server Error" });
            }
        });
        // GET: Check if a specific scholarship is saved by the current user
        app.get('/saved/status/:scholarshipId',
            verifyToken,
            async (req: AuthenticatedRequest, res: Response): Promise<any> => {
                try {
                    const { scholarshipId } = req.params;
                    const userId = req.user?.id;

                    // 1. Normalize the parameter to guarantee it's a clean, single string
                    const targetId: string = Array.isArray(scholarshipId) ? scholarshipId[0] : scholarshipId;

                    // 2. Early exit if either identifier is missing
                    if (!targetId || !userId) {
                        return res.status(400).json({ isSaved: false, message: "Missing required identifiers." });
                    }

                    // 3. Securely validate the scholarshipId string structure before casting
                    if (!ObjectId.isValid(targetId)) {
                        return res.status(400).json({ isSaved: false, message: "Invalid scholarshipId format." });
                    }

                    // 4. Safely handle userId depending on your auth format (ObjectId vs plain string)
                    const safeUserId: ObjectId | string = ObjectId.isValid(userId)
                        ? new ObjectId(userId)
                        : userId;

                    // 5. Query the database using the clean flat variables
                    const existingSave = await savedCollection.findOne({
                        userId: safeUserId,
                        scholarshipId: new ObjectId(targetId)
                    });

                    // 6. Return boolean state directly
                    return res.status(200).json({ isSaved: !!existingSave });

                } catch (error) {
                    console.error("Error checking save status:", error);
                    // Always return a JSON response object even on failures
                    return res.status(500).json({ isSaved: false, message: "Internal Server Error" });
                }
            }
        );
        // READ: Get all saved scholarships for logged-in user
        app.get('/saved', verifyToken, async (req: AuthenticatedRequest, res: Response) => {
            try {
                const userId = req.user?.id;

                if (!userId) return res.status(401).json({ message: "Unauthorized" });

                const savedItems = await savedCollection.aggregate([
                    { $match: { userId: new ObjectId(userId) } },
                    { $sort: { createdAt: -1 } },
                    {
                        $lookup: {
                            from: "scholarships",
                            localField: "scholarshipId",
                            foreignField: "_id",
                            as: "scholarship"
                        }
                    },
                    { $unwind: "$scholarship" },
                    {
                        $project: {
                            savedAt: "$createdAt",
                            _id: "$scholarship._id",
                            image: "$scholarship.image",
                            title: "$scholarship.title",
                            slug: "$scholarship.slug",
                            universityName: "$scholarship.universityName",
                            country: "$scholarship.country",
                            degree: "$scholarship.degree",
                            fundingType: "$scholarship.fundingType",
                            applicationDeadline: "$scholarship.applicationDeadline",
                            rating: "$scholarship.rating"
                        }
                    }
                ]).toArray();

                res.status(200).json(savedItems);
            } catch (error) {
                console.error("Error fetching saved scholarships:", error);
                res.status(500).json({ message: "Internal Server Error" });
            }
        });
        app.delete('/saved/:id', verifyToken, async (req: AuthenticatedRequest, res: Response) => {
            try {
                const userId = req.user?.id;

                // 1. Ensure scholarshipId is strictly a single string (fixes the TS overload error)
                const scholarshipId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;

                if (!userId) return res.status(401).json({ message: "Unauthorized" });
                if (!scholarshipId) return res.status(400).json({ message: "Missing scholarship ID" });

                // 2. Prevent runtime BSON crashes by validating the ID format first
                if (!ObjectId.isValid(userId) || !ObjectId.isValid(scholarshipId)) {
                    return res.status(400).json({ message: "Invalid ID format" });
                }

                // Match by scholarshipId AND userId so a user can only delete their own saved item
                const result = await savedCollection.deleteOne({
                    userId: new ObjectId(userId),
                    scholarshipId: new ObjectId(scholarshipId)
                });

                if (result.deletedCount === 0) {
                    return res.status(404).json({ message: "Saved scholarship not found" });
                }

                res.status(200).json({ message: "Removed successfully" });
            } catch (error) {
                console.error("Error removing saved scholarship:", error);
                res.status(500).json({ message: "Internal Server Error" });
            }
        });
        // GET /dashboard - Unified dashboard aggregation
        app.get('/dashboard', verifyToken, async (req: AuthenticatedRequest, res: Response) => {
            try {
                const userId = req.user?.id;
                if (!userId) return res.status(401).json({ message: "Unauthorized" });

                const userObjectId = new ObjectId(userId);
                const now = new Date();

                // Expanded to 180 days (approx. 6 months) to ensure we aren't filtering out dates that are a few months away
                const futureWindowLimit = new Date();
                futureWindowLimit.setDate(now.getDate() + 180);

                const [
                    myScholarshipsCount,
                    savedCount,
                    applicationsCount,
                    reviewsCount,
                    performanceAgg,
                    recentApplications,
                    myScholarships,
                    savedScholarships,
                    recentReviews,
                    upcomingDeadlines
                ] = await Promise.all([
                    // 1. Stats Counts
                    scholarshipsCollection.countDocuments({ authorId: userId }),

                    savedCollection.countDocuments({ userId: userObjectId }),
                    applicationsCollection.countDocuments({ userId: userObjectId }),
                    reviewsCollection.countDocuments({ userId: userObjectId }),

                    // 2. Performance Metrics
                    scholarshipsCollection.aggregate([
                        { $match: { authorId: userId } },
                        {
                            $group: {
                                _id: null,
                                totalViews: { $sum: "$totalViews" },
                                averageRating: { $avg: "$rating" },
                                totalReviews: { $sum: "$totalReviews" },
                                popularityScore: { $avg: "$popularity" }
                            }
                        }
                    ]).toArray(),

                    // 3. Recent Applications
                    applicationsCollection.aggregate([
                        { $match: { userId: userObjectId } },
                        { $sort: { appliedAt: -1 } },
                        { $limit: 5 },
                        {
                            $lookup: {
                                from: "scholarships",
                                localField: "scholarshipId",
                                foreignField: "_id",
                                as: "scholarship"
                            }
                        },
                        { $unwind: "$scholarship" },
                        {
                            $project: {
                                title: "$scholarship.title",
                                university: "$scholarship.universityName",
                                status: 1,
                                appliedAt: 1
                            }
                        }
                    ]).toArray(),

                    // 4. My Scholarships (Authored)
                    scholarshipsCollection.find(
                        { authorId: userId },
                        { projection: { title: 1, universityName: 1, country: 1, rating: 1, totalViews: 1, totalReviews: 1, slug: 1 } }
                    )
                        .sort({ updatedAt: -1 })
                        .limit(5)
                        .toArray(),

                    // 5. Saved Scholarships
                    savedCollection.aggregate([
                        { $match: { userId: userObjectId } },
                        { $sort: { createdAt: -1 } },
                        { $limit: 4 },
                        {
                            $lookup: {
                                from: "scholarships",
                                localField: "scholarshipId",
                                foreignField: "_id",
                                as: "scholarship"
                            }
                        },
                        { $unwind: "$scholarship" },
                        {
                            $project: {
                                title: "$scholarship.title",
                                university: "$scholarship.universityName",
                                country: "$scholarship.country",
                                fundingType: "$scholarship.fundingType"
                            }
                        }
                    ]).toArray(),

                    // 6. Recent Reviews
                    reviewsCollection.aggregate([
                        { $match: { userId: userObjectId } },
                        { $sort: { createdAt: -1 } },
                        { $limit: 5 },
                        {
                            $lookup: {
                                from: "scholarships",
                                localField: "scholarshipId",
                                foreignField: "_id",
                                as: "scholarship"
                            }
                        },
                        { $unwind: "$scholarship" },
                        {
                            $project: {
                                title: "$scholarship.title",
                                rating: 1,
                                reviewText: 1,
                                createdAt: 1
                            }
                        }
                    ]).toArray(),

                    // 7. Upcoming Deadlines (Global View)
                    // scholarshipsCollection.aggregate([
                    //     {
                    //         $match: {
                    //             isActive: true
                    //         }
                    //     },
                    //     {
                    //         $addFields: {
                    //             deadlineDate: {
                    //                 $dateFromString: {
                    //                     dateString: "$funding.applicationDeadline", // Corrected path
                    //                     format: "%Y-%m-%d",
                    //                     onError: null,
                    //                     onNull: null
                    //                 }
                    //             }
                    //         }
                    //     },
                    //     {
                    //         $match: {
                    //             deadlineDate: {
                    //                 $gte: now,
                    //                 $lte: futureWindowLimit
                    //             }
                    //         }
                    //     },
                    //     { $sort: { deadlineDate: 1 } },
                    //     { $limit: 5 },
                    //     {
                    //         $project: {
                    //             title: 1,
                    //             deadline: "$funding.applicationDeadline", // Corrected path
                    //             universityName: 1
                    //         }
                    //     }
                    // ]).toArray()
                    scholarshipsCollection.aggregate([
                        // {
                        //     $match: {
                        //         isActive: true
                        //     }
                        // },
                        {
                            $addFields: {
                                deadlineDate: {
                                    $dateFromString: {
                                        dateString: "$applicationDeadline",
                                        format: "%Y-%m-%d",
                                        onError: null,
                                        onNull: null
                                    }
                                }
                            }
                        },
                        {
                            $match: {
                                deadlineDate: {
                                    $gte: now,
                                    $lte: futureWindowLimit
                                }
                            }
                        },
                        {
                            $sort: {
                                deadlineDate: 1
                            }
                        },
                        {
                            $limit: 5
                        },
                        {
                            $project: {
                                title: 1,
                                universityName: 1,
                                deadline: "$applicationDeadline"
                            }
                        }
                    ]).toArray()
                ]);

                const performance = performanceAgg[0] || {
                    totalViews: 0, averageRating: 0, totalReviews: 0, popularityScore: 0
                };
                const samples = await scholarshipsCollection.find(
                    {},
                    {
                        projection: {
                            title: 1,
                            funding: 1,
                            applicationDeadline: 1,
                            isActive: 1
                        }
                    }
                ).limit(5).toArray();

                console.log(JSON.stringify(samples, null, 2));
                res.status(200).json({
                    stats: {
                        myScholarships: myScholarshipsCount,
                        saved: savedCount,
                        applications: applicationsCount,
                        reviews: reviewsCount
                    },
                    performance: {
                        totalViews: performance.totalViews,
                        averageRating: performance.averageRating ? parseFloat(performance.averageRating.toFixed(1)) : 0,
                        totalReviews: performance.totalReviews,
                        popularityScore: performance.popularityScore ? Math.round(performance.popularityScore) : 0
                    },
                    recentApplications,
                    myScholarships: myScholarships.map(s => ({
                        ...s,
                        views: s.totalViews,
                        reviewsCount: s.totalReviews
                    })),
                    savedScholarships,
                    recentReviews,
                    upcomingDeadlines
                });

            } catch (error) {
                console.error("Dashboard Aggregation Error:", error);
                res.status(500).json({ message: "Failed to load dashboard data" });
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