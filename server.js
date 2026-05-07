const express=require('express')
const log=require('express-dev-logger')
const cors=require('cors')
// server.js — add these two lines anywhere after you create your app
const app=express()

app.use(express.json())
app.use(log())
app.use(cors())
const { registerMonitorRoutes } = require('./domainCheck');
registerMonitorRoutes(app);



const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("connected to backend on port", PORT));

