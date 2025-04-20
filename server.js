const express = require('express');
const apiRoutes = require('./apiRoutes.js')

require('dotenv').config();

const app = express();
app.use(express.json());


app.use('/api',apiRoutes)

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
