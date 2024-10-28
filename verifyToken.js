const jwt = require('jsonwebtoken');

function verifyToken(req, res, next) {
    if (req.headers.authorization !== undefined) {
        let token = req.headers.authorization.split(" ")[1];

        jwt.verify(token, process.env.JWT_SECRET, (err, data) => {
            if (!err) {
                req.userId = data.userId;
                next();
            } else {
                res.status(403).send({ message: "Invalid Token" });
            }
        });
    } else {
        res.status(401).send({ message: "Please send a token" });
    }
}

module.exports = verifyToken;

// const jwt = require('jsonwebtoken');

// function verifyToken(req, res, next) {
//     if (req.headers.authorization !== undefined) {
//         let token = req.headers.authorization.split(" ")[1];

//         jwt.verify(token, process.env.JWT_SECRET, (err, data) => {
//             if (!err) {
//                 req.userId = data.userId;
//                 next();
//             } else {
//                 res.status(403).send({ message: "Invalid Token" });
//             }
//         });
//     } else {
//         res.status(401).send({ message: "Please send a token" });
//     }
// }

// module.exports = verifyToken;