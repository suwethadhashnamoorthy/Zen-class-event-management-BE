const router = require("express").Router();
const User = require("../Models/StudentSchema");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

router.post("/StudentDetails", async (req, res) => {
  const {
    name,
    email,
    password,
    phone,
    qualification,
    experience,
    passing,
    noticePeriod,
    github,
    portfolio,
    resume,
  } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new User({
        name,
        email,
        password: hashedPassword,
        phone,
        qualification,
        experience,
        passing,
        noticePeriod,
        github,
        portfolio,
        resume,
      });
      await newUser.save();
      return res.status(201).json({ message: "User created" });
    }
    return res.status(409).json({ message: "User already exists" });
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

router.get("/getAllStudents", async (req, res) => {
  try {
    const users = await User.find();
    res.status(200).json({ students: users });
  } catch (error) {
    console.error("Error fetching students:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});


router.get("/getStudent/:id", async (req, res) => {
  const studentId = req.params.id;

  try {
    const user = await User.findById(studentId);

    if (!user) {
      return res.status(404).json({ message: "Student not found" });
    }

    // Return the student details
    res.status(200).json({ student: user });
  } catch (error) {
    console.error("Error fetching student details:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

router.put("/updateStudent/:id", async (req, res) => {
  const studentId = req.params.id;
  const {
    name,
    phone,
    qualification,
    experience,
    passing,
    noticePeriod,
    github,
    portfolio,
    resume,
  } = req.body;

  try {
    const user = await User.findById(studentId);
    if (!user) {
      return res.status(404).json({ message: "Student not found" });
    }

    user.name = name;
    user.phone = phone;
    user.qualification = qualification;
    user.experience = experience;
    user.passing = passing;
    user.noticePeriod = noticePeriod;
    user.github = github;
    user.portfolio = portfolio;
    user.resume = resume;

    await user.save();

    res.status(200).json({ message: "Student details updated successfully" });
  } catch (error) {
    console.error("Error updating student details:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});



router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "Incorrect email or password" });
    }
    const passwordValidate = await bcrypt.compare(password, user.password);
    if (!passwordValidate) {
      return res.status(401).json({ message: "Incorrect email or password" });
    }
    const token = jwt.sign({ userId: user._id }, process.env.SECRET_KEY, {
      expiresIn: "1d",
    });
    res.status(200).json({ user, token });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

router.post("/resetpassword", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const resetToken = jwt.sign({ Id: user._id }, process.env.SECRET_KEY, {
      expiresIn: "1h",
    });

    // Send reset token via email
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL,
      to: user.email,
      subject: "Password Reset",
      text: `HI ${user.name},\n
      There was a request to change your password!\n
      If you did not make this request, please ignore this email.\n
      Otherwise, please click this link to change your password: http://localhost:3000/save-new-password/${resetToken}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log("Error sending email:", error);
        return res.status(500).json({ message: "Error sending email" });
      }
      res
        .status(200)
        .json({ message: "Password reset token sent", resetToken });
    });
  } catch (error) {
    console.log("Error during password reset:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

router.post("/savepassword", async (req, res) => {
  const { newPassword, resetToken } = req.body;
  // Verify reset token
  try {
    const decoded = jwt.verify(resetToken, process.env.SECRET_KEY);

    const userId = decoded.Id;
    const user = await User.findById(userId); // Use User instead of model

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedNewPassword; // Use password instead of Password
    await user.save();

    res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    console.log("Error verifying reset token:", error);
    res.status(400).json({ message: "Invalid reset token" });
  }
});

module.exports = router;
