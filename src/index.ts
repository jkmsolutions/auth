import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export interface Session {
    jwt?: string;
    refreshToken?: string;
}

declare global {
    namespace Express {
        interface Request {
            session?: Session;
        }
    }
}

export const authMiddleware = async (req: Request, res: Response, next: NextFunction): Promise<Response | void> => {
    const token = req.session?.jwt;

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    const verified = jwt.verify(token, process.env.JWT_SECRET as string);

    if (!verified) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    next();
}