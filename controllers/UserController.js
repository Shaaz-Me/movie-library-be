import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import User from "../models/User.js";
import crypto from 'crypto';

dotenv.config();

const createPassword = (password) => {
  const SALT = "MdShahzar";
  const ITERATIONS = 100000;
  const KEYLEN = 512;
  const DIGEST = "sha512";
  return crypto.pbkdf2Sync(password, SALT, ITERATIONS, KEYLEN, DIGEST).toString('hex');
}

export const signup = async (req, res, next) => {
  try {
    const { user } = req.body;
    const salt = 10;
    user['password'] = createPassword(user.password);
    const newUser = await User.create(user);
    res.status(201).send({ success: true, message: "user created" });
  } catch (error) {
    return next(error);
  }
};

export const login = async (req, res, next) => {
  try {
    const { user } = req.body;
    const myUser = await User.findOne({ email: user.email });
    if (myUser && (myUser.password === createPassword(user.password))) {
      const payload = {
        id: myUser._id,
        name: myUser.name,
        email: myUser.email,
      };
      const token = jwt.sign(payload, process.env.JWT_SECRET_KEY);
      return res
        .status(200)
        .send({ success: true, message: "Login successfull", token: token });
    }
    return res
      .status(400)
      .send({ success: false, message: "Wrong email or password" });
  } catch (error) {
    return next(error);
  }
};
