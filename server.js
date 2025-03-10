require("dotenv").config();
const express = require("express");
const express_session = require("express-session")
require("./config/database")
const userRouter = require("./routes/userRouter")
const scoreRouter = require("./routes/scoreRouter")


const PORT = process.env.PORT

const app = express();

app.use(express.json())
app.use(express_session({secret: "chrisH", resave: false, saveUninitialized: false}))
require("./middleware/passport")
app.use("/api/v1", userRouter)
app.use("/api/v1", scoreRouter)


app.listen(PORT, () => {
    console.log(`server is listening to port: ${PORT}`);
    
})