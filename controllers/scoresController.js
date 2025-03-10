const scoreModel = require("../models/score");
const userModel = require("../models/user");

exports.createScore = async (req, res) => {
  try {
    const { userId } = req.params;
    const {
      punctuality,
      classAssessment,
      personalDefence,
      assignment,
      attendance,
    } = req.body;

    const user = await userModel.findById(userId);

    if (!user) {
      return res.status(404).json({
        message: "Student not found",
      });
    }

    const prevScore = await scoreModel.find({ userId });

    const totalScore =
      punctuality + classAssessment + personalDefence + assignment + attendance;
    const score = new scoreModel({
      week: prevScore.length + 1,
      punctuality,
      classAssessment,
      personalDefence,
      assignment,
      attendance,
      total: totalScore,
      average: totalScore / 5,
      userId,
      name: user.fullName,
    });

    // save the changes to the database
    await score.save();

    res.status(201).json({
      message: "Score added successfuly",
      data: score,
    });
  } catch (error) {
    console.log(error.message);
    res.status(500).json({
      message: "Internal server error",
    });
  }
};

exports.getAllScores = async (req, res) => {
  try {
    const scores = await scoreModel.find();

    res.status(201).json({
      message: " all Scores in the database",
      data: scores,
    });
  } catch (error) {
    console.log(error.message);
    res.status(500).json({
      message: "Internal server error",
    });
  }
};

exports.getAllScoresByStudent = async (req, res) => {
  try {
    const { userId } = req.user;

    const user = await userModel.findById(userId);
    if (!user) {
      return res.status(404).json({
        message: "Student not found",
      });
    }
    const scores = await scoreModel.find({ userId });
    res.status(201).json({
      message: `all Scores for ${user.fullName}`,
      data: scores,
    });
  } catch (error) {
    console.log(error.message);
    res.status(500).json({
      message: "Internal server error",
    });
  }
};
