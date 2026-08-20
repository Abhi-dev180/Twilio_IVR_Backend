import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_twilio_ivr_key';

export default (req, res, next) => {
  // Get token from Authorization header
  const authHeader = req.headers['authorization'];
  
  if (!authHeader) {
    console.error('[AuthMiddleware] 401 Unauthorized: No authorization header provided for URL:', req.originalUrl);
    return res.status(401).json({ error: 'Access denied. No authorization header provided.' });
  }

  // Expecting format: Bearer <token>
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    console.error('[AuthMiddleware] 401 Unauthorized: Invalid token format for URL:', req.originalUrl, '- Header:', authHeader);
    return res.status(401).json({ error: 'Access denied. Invalid token format.' });
  }

  const token = parts[1];

  try {
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded; // Attach admin payload
    next();
  } catch (error) {
    console.error('JWT Verification failed:', error.message);
    return res.status(403).json({ error: 'Access denied. Invalid or expired token.' });
  }
};
