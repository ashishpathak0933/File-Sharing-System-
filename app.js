const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const puppeteer = require('puppeteer');
const indexRouter = require('./routes/index');
const usersRouter = require('./routes/users');
const axios = require('axios');
const mongoose = require('mongoose');
const multer = require('multer');
const {GridFsStorage} = require('multer-gridfs-storage');
const Grid = require('gridfs-stream');
const hasha = require('hasha');
const crypto = require('crypto');
const ThrottledReader = require('throttled-reader');
const CronJob = require('cron').CronJob;
const bodyParser = require("body-parser");
const BSON = require("bson");

const uri = 'mongodb://localhost:27017';
const uploadBucket = 'uploads'
const dbFile = require('./models/files');
const User = require('./models/user');
const adminReq = require('./models/admin');


const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const auth = require("./auth");
const http = require("http");

const jwtSecret = "4715aed3c946f7b0a38e6b534a9583628d84e96d10fbc04700770d572af3dce43625dd";
const blockingList = `https://www.tu-chemnitz.de/informatik/DVS/blocklist/`;

// view engine setup
const app = express();
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({extended: false}));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json())
app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, DELETE");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});
app.use('/', indexRouter);
app.use('/users', usersRouter);


mongoose.connect(uri);
const database = mongoose.connection;

database.on('error', (error) => {
    console.log(error)
});

let gfs, gridfsBucket;
database.once('connected', () => {
    console.log('Database Connected');
    gridfsBucket = new mongoose.mongo.GridFSBucket(database.db, {
        bucketName: uploadBucket
    });
    gfs = Grid(database.db, mongoose.mongo);
    gfs.collection(uploadBucket);
});


// Create storage engine
const storage = new GridFsStorage({
    url: uri,
    file: (req, file) => {
        return new Promise((resolve, reject) => {
            crypto.randomBytes(16, (err, buf) => {
                if (err) {
                    return reject(err);
                }
                const filename = buf.toString('hex') + path.extname(file.originalname);
                const fileInfo = {
                    filename: filename,
                    bucketName: uploadBucket
                };
                resolve(fileInfo);
            });
        });
    }
});

const upload = multer({storage});
const uiPath = {root: __dirname + "/ui"}

app.get("/upload.html", async function (req, res) {
    res.sendFile("upload.html", uiPath);
});

app.get("/login.html", async function (req, res) {
    res.sendFile("userlogin.html", uiPath);
});

app.get("/userdashboard.html", auth, async function (req, res) {
    const username = req.cookies.username;
    if (username === `icoolguy1000`)
        res.redirect(303, '/admin.html')
    else
        res.sendFile("userdashboard.html", uiPath);
});

app.get("/admin.html", async function (req, res) {
    res.sendFile("admindash.html", uiPath);
});

app.post('/upload', upload.array('file', 10), (req, res, next) => {
    for (let i = 0; i < req.files.length; i++) {
        let file = req.files[i];
        console.log(file)
        findFiles(file, res, req)
        res.write(JSON.stringify({
            download: 'download/' + file.filename
        }));
    }
    res.end();
});


app.post('/request', async (req, res, next) => {
    console.log(req.body.name)
    console.log(req.body.why)

    // Create random String
    const id = crypto.randomBytes(20).toString('hex');
    await adminReq.create({
        fileName: req.body.name,
        reason: req.body.why,
        requestId: id,
        resolved: false
    });

    res.send()
});
app.get('/request', (req, res, next) => {
    getAllAdminRequests().then(result => {
        res.json(result)
    })
});

app.post('/resolve/:requestId', (req, res, next) => {
    resolveAdminReq(req.params.requestId, res)
});

app.post('/decline/:requestId', (req, res, next) => {
    declinedRequestToBlock(req.params.requestId, res)
});

app.get('/download.html/:filename', (req, res) => {

    res.sendFile("downloadpage.html", uiPath);

    /*  let name = req.params.filename
      downloadFile(name, res, req)*/
});

app.get('/download/:filename', (req, res) => {
    let name = req.params.filename
    downloadFile(name, res, req)
});

app.post('/delete/:filename', auth, (req, res) => {
    removeFile(req.params.filename, res)
})

app.get('/files/:filename', (req, res) => {
    let name = req.params.filename
    findFiles(name, res, req)
});

app.get('/files', auth, (req, res) => {
    const username = req.cookies.username;
    getUsersFiles(username).then(result => {
        console.log(result)
        res.json(result)
    })
});

app.get('/check/:name', async (req, res) => {
    const fileHash = await getFileHash(req.params.name)
    let blockStatus = await getBlockList(fileHash)
    if(blockStatus)
        res.status(100).send()
    else
        res.status(200).send()

});

//auth user
app.post("/register", async (req, res) => {
    let encryptedUserPassword;
    try {
        // Get user input
        const {id, password} = req.body;
        let adminRole = false
        console.log(id)
        console.log(password)
        // Validate user input
        if (!(id && password)) {
            res.status(400).send("All input is required");

        }

        if (id === 'icoolguy1000')
            adminRole = true

        // check if user already exist
        // Validate if user exist in our database
        const oldUser = await User.exists({userName: id});
        if (oldUser) {
            console.log(oldUser)
            return res.status(409).send("User Already Exist. Please Login" + id);
        }

        //Encrypt user password
        encryptedUserPassword = await bcrypt.hash(password, 10);

        // Create user in our database
        const user = await User.create({
            userName: id, // sanitize: convert email to lowercase
            password: encryptedUserPassword,
            isAdmin: adminRole
        });

        user.token = jwt.sign(
            {user_id: user._id, id},
            jwtSecret,
            {
                expiresIn: "5h",
            }
        );

        // return new user
        res.cookie("bearer", user.token)
        res.cookie("username", id)
        res.status(201).json(user);
    } catch (err) {
        console.log(err);
    }
});

app.post("/login", async (req, res) => {
    try {
        // Get user input
        const {id, password} = req.body;
        console.log(id)
        console.log(password)

        // Validate user input
        if (!(id && password)) {
            res.status(400).send("All input is required");
        }
        // Validate if user exist in our database
        const user = await User.findOne({userName: id});

        if (user && (await bcrypt.compare(password, user.password))) {
            // Create token
            // save user token
            user.token = jwt.sign(
                {user_id: user._id, id},
                jwtSecret,
                {
                    expiresIn: "5h",
                }
            );

            // user
            res.cookie("bearer", user.token)
            res.cookie("username", id)
            return res.status(200).json(user);
        }
        return res.status(400).send("Invalid Credentials");
    } catch (err) {
        console.log(err);
    }
});

app.get("/welcome", auth, (req, res) => {
    res.status(200).send("Welcome to FreeCodeCamp 🙌");
});

app.post('/block/:filename', auth, (req, res) => {
    const hash = getFileHash(req.params.filename)
    //blockFile(tucCookies, hash, res)
});

app.post('/unblock/:filename', auth, (req, res) => {
    const hash = getFileHash(req.params.filename)
    removeFileFromBlockList(tucCookies, hash, res)
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
function findFiles(data, res, req) {
    gfs.files.find({filename: data.filename}).toArray((err, files) => {
        if (!files[0] || files.length === 0) {
            console.log("file not found")
            return
        } else {
            console.log("file found")
        }
        let file = files[0];
        const readStream = gridfsBucket.openDownloadStream(file._id);


        createHash(readStream).then(hash => {
            console.log(hash)
            const cookie = req.cookies.username;
            let newFile;
            if (cookie !== undefined) {
                console.log("cookie = " + cookie)
                newFile = new dbFile({
                    fileName: data.filename,
                    fileHash: hash,
                    blockedStatus: false,
                    userID: cookie,
                    date: new Date().getTime(),
                    filesize: formatBytes(data.size)
                });
            } else {
                console.log("emptyCookie")
                newFile = new dbFile({
                    fileName: data.filename,
                    fileHash: hash,
                    blockedStatus: false,
                    userID: '',
                    date: new Date().getTime(),
                    filesize: formatBytes(data.size)
                });
            }
            newFile.save().then(() => {
                /*res.status(200).json({
                    success: true,
                })*/
                getFileHash(data.filename)
            }).catch(err => res.status(500).json(err));
        });
    });
}


function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];

    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

let ipAddress;
let lock;

async function downloadFile(name, res, req) {

    const fileHash = await getFileHash(name)
    let blockStatus = await getBlockList(fileHash)
    console.log("status of file = "+blockStatus)

    if (blockStatus) {
        console.log("file is blocked")
        res.send("File is Blocked")
    } else {
        console.log("file is not blocked")
        gfs.files.find({filename: name}).toArray((err, files) => {
            if (!files[0] || files.length === 0) {
                console.log("file not found")
                return
            } else {
                console.log("file found")
            }
            let file = files[0];
            const readStream = gridfsBucket.openDownloadStream(file._id);
            const cookie = req.cookies.username;
            res.set('Content-Type', file.contentType);
            res.set('Content-Disposition', 'attachment; filename="' + file.filename + '"');
            if (cookie === undefined) {
                if (req.ip !== ipAddress) {
                    ipAddress = req.ip;
                    lock = true;
                } else if (lock) {
                    const timerDurationSeconds = 10 * 60;
                    let timerStart = new Date().getTime();
                    setInterval(() => {
                        console.log("Resetting timer...");
                        lock = false
                        timerStart = new Date().getTime();
                    }, timerDurationSeconds * 1000);

                    let elapsedSeconds = ((timerStart - new Date().getTime()) + 600000) / 1000;
                    let minutes = Math.floor(elapsedSeconds / 60).toFixed(0).padStart(2, "0");
                    let seconds = Math.round(elapsedSeconds % 60).toFixed(0).padStart(2, "0");
                    res.send(`wait for before downloading again ${minutes}:${seconds}`);
                    return
                }

                updateDate(name)
                const throttledStream = new ThrottledReader(readStream, {
                    rate: 100 * 1024 // In bytes per second
                });
                throttledStream.pipe(res);
            } else {
                readStream.pipe(res)
            }
        });
    }
}


function removeFile(name, res) {
    gfs.files.deleteOne({filename: name}).then(function () {
        console.log("Data deleted"); // Success
        dbFile.deleteOne({filename: name}).then(function () {
            console.log("Data deleted"); // Success
            res.status(200).send("Ales gut");
        }).catch(function (error) {
            console.log(error); // Failure
        });
    }).catch(function (error) {
        console.log(error); // Failure
    });
}

async function getUsersFiles(username) {
    console.log("username -" + username)
    let result = await dbFile.find({userID: username});
    console.log(result)
    return result
}

async function getAllAdminRequests() {
    let result = await adminReq.find({resolved: false});
    console.log(result)
    return result
}

async function declinedRequestToBlock(id, res) {
    let result = await adminReq.findOne({requestId: id});
    result.resolved = true
    await result.save();
    res.status(200).send();
}


async function getFileHash(fileName) {
    const filter = {fileName: fileName};
    let doc = await dbFile.findOne(filter);
    return doc.fileHash;

    /* doc.userName = 'asdas';
     await doc.save();
     doc = await dbFile.findOne();
     console.log(doc)*/

}


async function updateDate(filename) {
    const filter = {fileName: filename};
    let doc = await dbFile.findOne(filter);
    doc.date = new Date();
    await doc.save();
}

async function createHash(stream) {
    return await hasha.fromStream(stream, {algorithm: 'sha256'});
}

///////////////////////////////////////////////////////////////////////////////////////////////
async function getCookies() {
    const browser = /* puppeteer.launch({headless: false});*/ await puppeteer.launch();
    const page = await browser.newPage();
    await page.goto(blockingList, {waitUntil: 'networkidle0'});
    await page.waitForSelector('#krbSubmit', {visible: true, timeout: 0})
    await page.authenticate({'username': 'mushu', 'password': 'Mustansir!1995'});

    /* Run javascript inside of the page */
    await page.evaluate(() => {
        document.getElementById('krbSubmit').click()

    });
    await page.waitForSelector('#username', {visible: true, timeout: 0})
    await page.evaluate(() => {
        document.querySelector('#username').value = 'mushu'
        document.querySelector("#top > div > main > div > form > input.btn.btn-default").click()
    })
    await page.waitForSelector('#password', {visible: true, timeout: 0})
    await page.evaluate(() => {
        document.querySelector("#password").value = 'Mustansir!1995'
        document.querySelector("#top > div > main > div > form > input.btn.btn-default").click()
    })

    await page.waitForSelector('body > h1', {visible: true, timeout: 0})
    await page.evaluate(() => {
        return document.querySelector("body > h1:nth-child(1)").innerHTML
    })

    /* Outputting what we scraped */
    //const html = await page.content();
    //  console.log(aa)
    const cook = await page.cookies();
    let setupCookie = cook[0].name + "=" + cook[0].value + ";" + cook[1].name + "=" + cook[1].value + ";";
    console.log(setupCookie)
    await browser.close();
    return setupCookie
}

let setupC;

async function blockFile(hash) {
    if (setupC === undefined)
        setupC = await getCookies()
    console.log(setupC)
    axios.put(blockingList + hash, {},
        {
            headers: {
                cookie: setupC,
                host: "www.tu-chemnitz.de"
            },

        })
        .then(re => {
            console.log('is the file blocked' + re.status)
        })
        .catch(error => {
            console.log(error);
        });
}

async function removeFileFromBlockList(hash) {
    if (setupC === undefined)
        setupC = await getCookies()

    axios.delete(blockingList + hash,
        {
            headers: {
                cookie: setupC,
                host: "www.tu-chemnitz.de"
            },

        })
        .then(res => {
            console.log(`statusCode: ${res.status}`);
            //   console.log(res);
            return res.status
        })
        .catch(error => {
            console.error(error);
            return error
        });
}


async function resolveAdminReq(id, res) {
    let result = await adminReq.findOne({requestId: id});
    result.resolved = true
    await result.save();
    const filter = {fileName: result.fileName};
    let doc = await dbFile.findOne(filter);
    //console.log("is the file blocked? + "+  await getBlockList(tucCookies, doc.fileHash))
    if (!await getBlockList(doc.fileHash)) {
        console.log("blocking file")
        doc.blockStatus = true
        await doc.save();
        blockFile(doc.fileHash).then(() => res.status(100))

    } else {
        console.log("unblocking file")
        doc.blockStatus = false
        await doc.save();
        removeFileFromBlockList(doc.fileHash).then(() => res.status(200))
    }

}


async function getBlockList(hash) {
    if (setupC === undefined)
        setupC = await getCookies()
    return axios.get(blockingList + hash,
        {
            headers: {
                cookie: setupC,
                host: "www.tu-chemnitz.de"
            },

        })
        .then(res => {
            console.log('status code =' + res.status)
            return res.status === 210;
        })
        .catch(error => {
            console.log(error)
            return false
        });
}

const job = new CronJob(
    '0 0 0 * * *',
    async function () {
        let timestamp = new Date().getTime() + (12 * 24 * 60 * 60 * 1000)
        for await (const doc of dbFile.find()) {
            if (timestamp > doc.date) {
                removeFile(doc.name)
            }

        }

    },
    null,
    true,
    'America/Los_Angeles'
);
job.start()


module.exports = app;
