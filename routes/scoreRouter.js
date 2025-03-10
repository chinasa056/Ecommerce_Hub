const { createScore } = require("../controllers/scoresController");
const { adminAuth } = require("../middleware/authentication");

const router = require("express").Router();

router.post ("/addscore/:userId", adminAuth, createScore)

module.exports = router;