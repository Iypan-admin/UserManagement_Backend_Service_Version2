const jwt = require('jsonwebtoken');
require('dotenv').config();

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).send('Token is required');

    jwt.verify(token.split(' ')[1], process.env.SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).send('Invalid token');
        req.user = decoded;
        next();
    });
};

module.exports = verifyToken;
