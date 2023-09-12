const mongoose = require("mongoose");

const studentSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  batch: {
    type: String,
    default: "B47-WD2 Tamil",
  },
  phone: {
    type: String,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  qualification: {
    type: String,
  },
  experience: {
    type: String,
  },
  passing: {
    type: String,
  },
  noticePeriod: {
    type: String,
  },
  github: {
    type: String,
  },
  portfolio: {
    type: String,
  },
  resume: {
    type: String,
  },
});

module.exports = mongoose.model("Student", studentSchema, "students");
