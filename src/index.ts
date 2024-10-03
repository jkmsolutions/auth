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

export const authMiddleware = async (req: Request, res: Response, next: NextFunction): Promise<any> => {
    const token = req.session?.jwt;

    if (!token) {
        res.status(401).json({ message: 'Unauthorized' });
        return;
    }

    try {
        jwt.verify(token, process.env.JWT_SECRET as string);
        const { steamid64 } = decodeToken(token);
        if (!steamid64) {
            res.status(401).json({ message: 'Unauthorized' });
            return;
        }
        next();
    } catch (err) {
        if (err instanceof TokenExpiredError) {
            res.status(401).json({ message: 'Token expired' });
            return;
        }

        res.status(401).json({ message: 'Unauthorized' });
        return;
    }
};

export const decodeToken = (token: string): DecodedToken => {
    return jwt.decode(token) as DecodedToken;
}