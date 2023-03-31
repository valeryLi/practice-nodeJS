require("colors");
const connectDb = require("../config/db");
const asyncHandler = require("express-async-handler");
const auth = require("./middlewares/auth");

const path = require("path");
const configPath = path.join(__dirname, "..", "config", ".env");
require("dotenv").config({ path: configPath });
const express = require("express");
const UserModel = require("./models/userModel.js");
const RoleModel = require("./models/roleModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use("/api/v1", require("./routes/booksRoutes"));

// Registration - save new user in DB
// We have 4 steps of validation(frontend, joi, controllers validation(when we have in model requered and not requered fields), DB validation)
// bcrypt works with all versions. BcryptJS works only with stable versions(LTS- long term support)
app.post(
  "/register",
  (req, res, next) => {
    console.log("worked joi");
    next();
  },
  asyncHandler(async (req, res) => {
    //get data from user
    const { email, password } = req.body;
    if (!email || !password) {
      res.status(400);
      throw new Error("Provide all required fields !");
    }
    //check this user in DB or his exists
    const candidate = await UserModel.findOne({ email });
    //if user exists, send message that he exists
    if (candidate) {
      res.status(400);
      throw new Error("User already exists!");
    }
    //if user not in DB, cash password
    const hashPassword = bcrypt.hashSync(password, 10);
    //save user in DB
    const userRole = await RoleModel.findOne({ value: "ADMIN" });
    const user = await UserModel.create({
      ...req.body,
      password: hashPassword,
      roles: [userRole.value],
    });

    if (!user) {
      res.status(400);
      throw new Error("Cannot save user!");
    }

    res.status(201).json({
      code: 201,
      message: "Registration success!",
      data: user.email,
    });
  })
);

// Authantification - check data which send user with the data in DB

app.post(
  "/login",
  (req, res, next) => {
    next();
  },
  asyncHandler(async (req, res) => {
    //get data from user
    const { email, password } = req.body;
    if (!email || !password) {
      res.status(400);
      throw new Error("Provide all required fields !");
    }
    //check this user in DB or his exists
    const user = await UserModel.findOne({ email });
    // if user exist in DB -> decrypting the password
    const isValidPassword = bcrypt.compareSync(password, user?.password || "");
    //  if not found user or not decrypt the password -> message "wrong password or login"
    if (!user || !isValidPassword) {
      res.status(400);
      throw new Error("Invalid login or password!");
    }
    //generate a token and save in DB
    const token = generateToken({
      friends: ["Nastja", "Andrej", "Maksim", "Sergey", "Anatoliy"],
      id: user._id,
      email: user.email,
      roles: user.roles,
    });
    user.token = token;

    const userWithToken = await user.save();
    if (!userWithToken) {
      res.status(400);
      throw new Error("Cannot save token!");
    }

    res.status(200).json({
      code: 200,
      message: "Login success!",
      data: { email: user.email, token: user.token },
    });
  })
);

function generateToken(data) {
  return (token = jwt.sign(data, "pizza", { expiresIn: "8h" }));
}

// Authorization - check or the user can do something(if user has rights)

// Logout - log out and losing rights

app.get(
  "/logout",
  auth,
  asyncHandler(async (req, res) => {
    const { id } = req.user;
    const user = await UserModel.findById(id);
    if (!user) {
      res.status(400);
      throw new Error("Cannot find user!");
    }

    user.token = null;

    const updateUser = await user.save();
    if (!updateUser) {
      res.status(400);
      throw new Error("Cannot logout user!");
    }

    res.status(200).json({
      code: 200,
      message: "Logout success!",
    });
  })
);

app.use("*", (req, res, next) => {
  res.status(404).json({
    code: 404,
    message: "Not found",
  });
  next();
});

app.use((err, req, res, next) => {
  const statusCode = res.statusCode || 500;

  res.status(statusCode);
  res.json({
    code: statusCode,
    message: err.message,
    stack: err.stack,
  });
});

connectDb();

app.listen(process.env.PORT, () => {
  console.log(`Server  running on Port ${process.env.PORT} `.green.bold.italic);
});

// console.log("Hello fom Andrey".green.italic.bold);
// console.log("Hello fom Andrey".yellow.italic.bold);
// console.log("Hello fom Andrey".red.italic.bold);
