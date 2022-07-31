const jwt = require("jsonwebtoken");

const jwtSecret = "4715aed3c946f7b0a38e6b534a9583628d84e96d10fbc04700770d572af3dce43625dd";

const verifyToken = (req, res, next) => {
    const token =
        req.body.token || req.query.token || req.headers["x_access_token"]|| req.cookies.bearer;

    if (!token) {
        return res.redirect(303,'/login.html')  ;
    }
    try {
        req.user = jwt.verify(token, jwtSecret);
    } catch (err) {
        return res.status(401).send("Invalid Token");
    }
    return next();
};

module.exports = verifyToken;