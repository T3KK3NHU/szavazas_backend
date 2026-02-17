const express = require('express')
const cors = require('cors')
const cookieParser = require('cookie-parser')
const mysql = require('mysql2/promise')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const emailValidator = require('node-email-verifier');

// -- config -- 
const PORT = 3000;
const HOST = 'localhost'
const jwt_SECRET = 'nagyon_nagyon_titkos_egyedi_jelszo'
const JWT_EXPIRES_IN='7d'
const COOKIE_NAME='auth_token'

// cookie beállitás

const COOKIE_OPTS = {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    path:'/',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 nap

}

// --- adatbázis beállitás ---
const db = mysql.createPool({
    host: 'localhost', // sulis szerver miatt majd átíródik
    port: '3306', // sulis szerver miatt majd átíródik
    user: 'root',
    password: '',
    database: 'szavazas'
})

// --- AP ---
const app = express();

app.use(express.json())
app.use(cookieParser())
app.use(cors({
    origin:'*',
    credentials: true
}))

// --- vegpontok ---

app.post('/regisztracio', async (req, res) => {
    const {email, felhasznalonev, jelszo, admin} = req.body;

    // bemeneti adatok ellenőrzése
    if (!email || !felhasznalonev || !jelszo || !admin)
    {
        return res.status(400).json({message: "Hiányos bemeneti adatok"})    
    }

    
    try {
        // valós email cím-e
        const isValid = await emailValidator(email)
        if (!isValid)
        {
        return res.status(401).json({message: "nem valós emailt adtál meg"})    
        }

        // ellenőrizni a felhasználónevet és emailt, hogy egyedi-e
        const emailFelhasznalonevSQL = 'SELECT * FROM felhasznalok WHERE email = ? OR felhasznalo = ?'
        const [exists] = await db.query(emailFelhasznalonevSQL, [email,felhasznalonev]);
        if (exists.length)
        {
            return res.status(402).json({message: "Az email cim vagy felhasználónév foglalt"})    
        }

        // regisztráció elvégzése
        const hash =  await bcrypt.hash(jelszo,10);
        const regisztracioSQL = 'INSERT INTO felhasznalok (email, felhasznalonev, jelszo, admin) VALUES (?,?,?,?)'
        const [result] = await db.query(regisztracioSQL, [email,felhasznalonev,hash,admin])

        // válasz a felhasználónak
        return res.status(200).json({
            message: "sikeres regisztráció",
            id: result.insertId
        })

    } catch (error) {
        console.log(error);
        return res.status(500).json({message: "Szerverhiba"})
    }

})

app.post('/belepes', async (req,res) => {
    const {felhasznalonevVagyEmail, jelszo} =req.body;
    if (!felhasznalonevVagyEmail || !jelszo)
    {
        return res.status(400).json({message: "hiányos belépési adatok"})
    }

    // meg kell kérdezni, hogy a megadott fiókhoz (email,felhasznalonev) milyen jelszó tartozik
    try {
        const isValid = await emailValidator(felhasznalonevVagyEmail)
        let hashJelszo = "";
        let user = []
    if (isValid)
    {
        // email + jelszót adott meg belépéskor
        const sql = 'SELECT * FROM felhasznalok WHERE email = ?'
        const [rows] = await db.query(sql, [felhasznalonevVagyEmail]);
        if (rows.length)
        {
            user=rows[0];
            hashJelszo =user.jelszo;
        }else{
            return res.status(401).json({message: "Ezzel az email cimmel még nem regisztráltak"})
        }
    }else{
        // felhasználónév + jelszót adott meg belépéskor
        const sql = 'SELECT * FROM felhasznalok WHERE felhasznalonev = ?'
        const [rows] = await db.query(sql, [felhasznalonevVagyEmail]);
        if (rows.length)
        {
            user=rows[0];
            hashJelszo =user.jelszo;
        }else{
            return res.status(401).json({message: "Ezzel a felhasználónévvel még nem regisztráltak"})
        }
    }

    const ok = bcrypt.compare(jelszo, hashJelszo)//felhasznalonev vagy emailhez tartozó jelszó
    if (ok){
        return res.status(403).json({message: "Rossz jelszót adtál meg!"})
    }
    
        const token = jwt.sign(
            {id: user.id, email:user.email, felhasznalonev: user.felhasznalonev},
            jwt_SECRET,
            {expiresIn: JWT_EXPIRES_IN}
        )    

    res.cookie(COOKIE_NAME, token, COOKIE_OPTS)
    res.status(200).json({message: "Sikeres belépés"})

    } catch (error) {
        console.log(error)
        return res.status(500).json({message: "Szerverhiba"})
    }
})

app.get('/adataim', auth, async (req, res) => {

})

// --- szerver elinditás ---
app.listen(PORT, HOST, () =>{
    console.log(`API Fut: http://${HOST}:${PORT}/`)
})