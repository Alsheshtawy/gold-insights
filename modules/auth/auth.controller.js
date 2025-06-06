import { User } from "../../models/user.model.js";
import { handleError } from "../../middlewares/catchError.js";
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

export const register = handleError(async (req, res, next) => {
    let user = new User(req.body); 
    await user.save();
    let token = jwt.sign({ userId: user._id, role: user.role }, "secretkey");
    res.json({ message: "User registered successfully", user, token });
});

export const login = handleError(async (req, res, next) => {
    let user = await User.findOne({ email: req.body.email });
    if (user && bcrypt.compareSync(req.body.password, user.password)) {
        let token = jwt.sign({ userId: user._id, role: user.role }, "secretkey");
        return res.json({ message: "login successfully", user, token });
    }
    return res.json({ message: "Invalid email or password" });
});

export const changePassword = handleError(async (req, res, next) => {
  const { email, password: oldpassword, newpassword: newPassword } = req.body;

  if (!email || !oldpassword || !newPassword) {
    return next(new Error("All fields are required"));
  }

  const user = await User.findOne({ email });

  if (!user) {
    return next(new Error("Invalid email or password"));
  }

  const isMatch = bcrypt.compareSync(oldpassword, user.password);

  if (!isMatch) {
    return next(new Error("Invalid email or password"));
  }

  
  const updatedUser = await User.findOneAndUpdate({ email },{password: newPassword,passwordChangedAt: Date.now()},{ new: true });

  const token = jwt.sign({ userId: updatedUser._id, role: updatedUser.role },"secretkey");

  return res.json({message: "Password changed successfully",user: updatedUser,token});
});



export const protectedRouter = handleError(async (req, res, next) => {
    const { token } = req.headers;
    if (!token) return next(new Error("token is required"));

    let userPayload;
    try {
        userPayload = jwt.verify(token, "secretkey");
    } catch (err) {
        return next(new Error("invalid token", 401));
    }

    const user = await User.findById(userPayload.userId);
    if (!user) return next(new Error("User not found", 404));

    if (user.passwordChangedAt) {
        const passwordTime = parseInt(user.passwordChangedAt.getTime() / 1000);
        if (passwordTime > userPayload.iat) {
            return next(new Error("invalid token, please login again", 401));
        }
    }

    req.user = user;
    next();
});
