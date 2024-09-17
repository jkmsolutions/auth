import { Request, Response, NextFunction } from 'express';
import jwt, { TokenExpiredError } from 'jsonwebtoken';

export interface Session {
    jwt?: string;
    refreshToken?: string;
}

export interface DecodedToken {
    steamid64: string;
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

    try {
        jwt.verify(token, process.env.JWT_SECRET as string);
        next();
    } catch (err) {
        if (err instanceof TokenExpiredError) {
            return res.status(401).json({ message: 'Token expired' });
        }

        return res.status(401).json({ message: 'Unauthorized' });
    }
};

export const decodeToken = (token: string): DecodedToken => {
    return jwt.decode(token) as DecodedToken;
}