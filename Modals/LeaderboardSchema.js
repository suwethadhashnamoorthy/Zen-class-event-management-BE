const mongoose = require("mongoose");

const leaderboardSchema = new mongoose.Schema({
  name: {
    type: String,
  },
  batch:{
    type:String,
    default:"B39WE Tamil"
  },
  
  learning: {
    type: String,
    default: "",
  }
 
});

module.exports = mongoose.model("Leaderboard", leaderboardSchema,"Leaderboard");
