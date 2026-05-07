const express=require('express')
const log=require('express-dev-logger')
// server.js — add these two lines anywhere after you create your app
const app=express()

app.use(express.json())
app.use(log())
const { registerMonitorRoutes } = require('./domainCheck');
registerMonitorRoutes(app);



app.listen(5000,()=>console.log("connected to backedn"))


