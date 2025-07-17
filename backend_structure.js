require('dotenv').config();

const express = require('express');   // creare API REST
const cors = require('cors');   // gestisce le richieste cross-origin
const mysql = require('mysql2/promise');    // driver MySQL
const AWS = require('aws-sdk');   // integra servizi AWS
const jwt = require('jsonwebtoken');    // crea e verifica token JWT per autenticazione
const jwkToPem = require('jwk-to-pem');   // convertire le chiavi JWK (che Cognito fornisce) nel formato PEM necessario per la verifica
const axios = require('axios');   // scaricare le chiavi pubbliche di Cognito

const app = express();    // crea app Express
const port = process.env.PORT || 8080;    // imposta la porta

let pems;   // cache per chiavi pubbliche di Cognito

// Middleware
app.use(cors());    // abilita CORS per tutte le route
app.use(express.json());    // abilita parsing automatico del JSON nelle richieste

// Configurazione AWS
const cognito = new AWS.CognitoIdentityServiceProvider({
  region: process.env.AWS_REGION    // configurato con regione AWS delle variabili d'ambiente
});
const crypto = require('crypto');

const s3 = new AWS.S3({
  region: process.env.AWS_REGION    // configurato con regione AWS delle variabili d'ambiente
});

// Configurazione Database (MySQL)
const dbConfig = {
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  port: 3306,
  ssl: { rejectUnauthorized: false },
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000
};

const pool = mysql.createPool(dbConfig); // crea pool di connessioni MySQL per gestire le richieste multiple

// Middleware per autenticazione
// verifica se la richiesta contiene un token JWT nell'header "Authorization"
async function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Estrae il token Bearer

    if (!token) {
        return res.status(401).json({ error: 'Access token non fornito.' });
    }

    try {
        const decodedJwt = jwt.decode(token, { complete: true }); // Decodifica senza verificare per ottenere KID
        if (!decodedJwt) {
            return res.status(401).json({ error: 'Token non valido.' });
        }

        const kid = decodedJwt.header.kid; // Ottieni il KID dall'header
        const currentPems = await getCognitoPems(); // Ottieni le chiavi pubbliche

        const pem = currentPems[kid];
        if (!pem) {
            return res.status(401).json({ error: 'Chiave di verifica del token non trovata.' });
        }

        // Verifica il token usando la chiave pubblica di Cognito
        const verifiedToken = jwt.verify(token, pem, { algorithms: ['RS256'] });

        // Puoi anche verificare l'issuer e l'audience (client_id) qui
        // if (verifiedToken.iss !== `https://cognito-idp.${process.env.COGNITO_REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}`) {
        //     return res.status(401).json({ error: 'Issuer del token non valido.' });
        // }
        // if (verifiedToken.aud !== process.env.COGNITO_CLIENT_ID) {
        //     return res.status(401).json({ error: 'Audience del token non valida.' });
        // }

        req.user = verifiedToken; // Aggiungi i dati dell'utente alla richiesta
        next(); // Continua con la route
    } catch (error) {
        console.error('Errore nella verifica del token:', error);
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token scaduto. Effettua nuovamente il login.' });
        }
        return res.status(401).json({ error: 'Token non valido o scaduto.' });
    }
}

// scarica chiavi pubbliche di Cognito
async function getCognitoPems() {
    if (pems) return pems; // Usa la cache se già caricate

    const jwksUrl = `https://cognito-idp.${process.env.COGNITO_REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}/.well-known/jwks.json`;
    try {
        const response = await axios.get(jwksUrl);
        const jwks = response.data.keys;
        pems = {};
        for (let i = 0; i < jwks.length; i++) {
            const jwk = jwks[i];
            const pem = jwkToPem({ kty: jwk.kty, n: jwk.n, e: jwk.e });
            pems[jwk.kid] = pem;
        }
        return pems;
    } catch (error) {
        console.error('Errore nel recupero delle chiavi JWKS di Cognito:', error);
        throw new Error('Impossibile recuperare le chiavi pubbliche Cognito.');
    }
}

// ============== AUTHENTICATION ROUTES ==============

// Login utente con Cognito
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email e password richiesti' });
    }

    const CLIENT_ID = process.env.COGNITO_CLIENT_ID;
    const CLIENT_SECRET = process.env.COGNITO_CLIENT_SECRET;

    const hmac = crypto.createHmac('sha256', CLIENT_SECRET);
    hmac.update(email + CLIENT_ID);
    const secretHash = hmac.digest('base64');

    const params = {
      AuthFlow: 'ADMIN_NO_SRP_AUTH',
      UserPoolId: process.env.COGNITO_USER_POOL_ID,
      ClientId: CLIENT_ID,
      AuthParameters: {
        USERNAME: email,
        PASSWORD: password,
        SECRET_HASH: secretHash
      }
    };
    
    const result = await cognito.adminInitiateAuth(params).promise();
    
    // Genera anche un JWT token per l'app
    const token = jwt.sign(
      { 
        email: email,
        cognitoSub: result.AuthenticationResult.AccessToken 
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      message: 'Login effettuato con successo',
      accessToken: result.AuthenticationResult.AccessToken,
      refreshToken: result.AuthenticationResult.RefreshToken,
      idToken: result.AuthenticationResult.IdToken,
      appToken: token
    });
    
  } catch (error) {
    console.error('Errore login:', error);
    if (error.code === 'NotAuthorizedException') {
      res.status(401).json({ error: 'Credenziali non valide' });
    } else if (error.code === 'UserNotConfirmedException') {
      res.status(401).json({ error: 'Utente non confermato' });
    } else {
      res.status(500).json({ error: 'Errore interno del server' });
    }
  }
});

// Registrazione utente con Cognito
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, genres, mood } = req.body;
    
    if (!name || !email || !password || !genres || !Array.isArray(genres) || genres.length === 0 || !mood) {
      return res.status(400).json({ error: 'Dati mancanti o non validi' });
    }
    
    const cognitoParams = {
      UserPoolId: process.env.COGNITO_USER_POOL_ID,
      Username: email,
      UserAttributes: [
        { Name: 'email', Value: email },
        { Name: 'name', Value: name },
      ],
      TemporaryPassword: password,
      MessageAction: 'SUPPRESS' 
    };
    
    const cognitoResult = await cognito.adminCreateUser(cognitoParams).promise();
    
    await cognito.adminSetUserPassword({
      UserPoolId: process.env.COGNITO_USER_POOL_ID,
      Username: email,
      Password: password,
      Permanent: true
    }).promise();

    const genresToSave = JSON.stringify(genres);
    const cognitoSubFromCognito = cognitoResult.User.Username;
    
    const query = `
      INSERT INTO utenti (nome, email, generi_preferiti, mood_attuale, cognito_sub, data_creazione, data_aggiornamento)
      VALUES (?, ?, ?, ?, ?, NOW(), NOW())
    `;
    
    const values = [
      name,
      email,
      //JSON.stringify(genres),
      genresToSave, 
      mood,
      //cognitoResult.User.Username
      cognitoSubFromCognito
    ];
    
    const [result] = await pool.execute(query, values);
    
    const [userRows] = await pool.execute(
      'SELECT id, nome, email, generi_preferiti, mood_attuale, data_creazione, data_aggiornamento FROM utenti WHERE id = ?',
      [result.insertId]
    );
    
    let userToReturn = null;
    if (userRows.length > 0) {
      const user = userRows[0];
      let parsedGenres = [];
      
      if (user.generi_preferiti !== null && user.generi_preferiti !== undefined) {
        try {
          if (Array.isArray(user.generi_preferiti)) {
            parsedGenres = user.generi_preferiti;
          } else if (typeof user.generi_preferiti === 'string') {
            if (user.generi_preferiti.startsWith('[') && user.generi_preferiti.endsWith(']')) {
              parsedGenres = JSON.parse(user.generi_preferiti);
            } else {
              parsedGenres = user.generi_preferiti.split(',').map(g => g.trim());
            }
          }
        } catch (e) {
          console.error("Errore nel parsing dei generi:", e);
          console.error("Valore generi_preferiti:", user.generi_preferiti);
          if (typeof user.generi_preferiti === 'string') {
            parsedGenres = user.generi_preferiti.split(',').map(g => g.trim());
          } else {
            parsedGenres = [];
          }
        }
      }
      
      userToReturn = {
        id: user.id,
        nome: user.nome,
        email: user.email,
        generi_preferiti: parsedGenres,
        mood_attuale: user.mood_attuale,
        data_creazione: user.data_creazione,
        data_aggiornamento: user.data_aggiornamento
      };
    }
    
    res.status(201).json({
      message: 'Utente registrato con successo',
      user: userToReturn
    });
    
  } catch (error) {
    console.error('Errore registrazione:', error);
    if (error.code === 'UsernameExistsException') {
      res.status(409).json({ error: 'Email già registrata' });
    } else if (error.code === 'ER_DUP_ENTRY') {
      res.status(409).json({ error: 'Email già registrata' });
    } else {
      res.status(500).json({ error: 'Errore interno del server' });
    }
  }
});

// Logout utente
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    const { accessToken } = req.body;
    
    if (accessToken) {
      await cognito.globalSignOut({
        AccessToken: accessToken
      }).promise();
    }
    
    res.json({ message: 'Logout effettuato con successo' });
    
  } catch (error) {
    console.error('Errore logout:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// ============== USER ROUTES ==============

// Health check
// verifica che il server sia attivo
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Ready check
// verifica che il DB sia raggiungibile
app.get('/ready', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.execute('SELECT 1');
    connection.release();
    res.status(200).json({ status: 'READY' });
  } catch (error) {
    res.status(503).json({ status: 'NOT_READY', error: error.message });
  }
});

// Ottenere profilo utente
// richiede autenticazione, estrae ID utente dall'URL e restituisce i dati del profilo utente
app.get('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const query = `
      SELECT id, nome, email, generi_preferiti, mood_attuale, data_creazione, data_aggiornamento
      FROM utenti WHERE id = ?
    `;
    
    const [rows] = await pool.execute(query, [id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Utente non trovato' });
    }
    
    const user = rows[0];
    
    // Gestione sicura del parsing dei generi
    let parsedGenres = [];
    if (user.generi_preferiti !== null && user.generi_preferiti !== undefined) {
      try {
        // Verifica se è già un array
        if (Array.isArray(user.generi_preferiti)) {
          parsedGenres = user.generi_preferiti;
        } else if (typeof user.generi_preferiti === 'string') {
          // Prova a fare il parsing JSON
          if (user.generi_preferiti.startsWith('[') && user.generi_preferiti.endsWith(']')) {
            parsedGenres = JSON.parse(user.generi_preferiti);
          } else {
            // Se è una stringa separata da virgole, dividila
            parsedGenres = user.generi_preferiti.split(',').map(g => g.trim());
          }
        }
      } catch (e) {
        console.error("Errore nel parsing dei generi:", e);
        console.error("Valore generi_preferiti:", user.generi_preferiti);
        // Fallback: prova a dividere per virgole
        if (typeof user.generi_preferiti === 'string') {
          parsedGenres = user.generi_preferiti.split(',').map(g => g.trim());
        } else {
          parsedGenres = [];
        }
      }
    }
    
    // Restituisci l'utente con i generi parsati correttamente
    const userResponse = {
      id: user.id,
      nome: user.nome,
      email: user.email,
      generi_preferiti: parsedGenres,
      mood_attuale: user.mood_attuale,
      data_creazione: user.data_creazione,
      data_aggiornamento: user.data_aggiornamento
    };
    
    res.json(userResponse);
    
  } catch (error) {
    console.error('Errore recupero utente:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

app.get('/api/users/profile', authenticateToken, async (req, res) => {
    try {
        // req.user conterrà i dati decodificati dal token (es. sub, email, name)
        const cognitoSub = req.user.sub; // Questo è l'ID univoco dell'utente Cognito

        console.log('Cognito Sub estratto dal token:', cognitoSub);

        // Recupera i dati dell'utente dal tuo DB locale usando il cognitoSub
        const [rows] = await pool.execute(
            'SELECT id, nome, email, generi_preferiti, mood_attuale FROM utenti WHERE cognito_sub = ?',
            [cognitoSub]
        );

        console.log('Risultato query DB (rows):', rows);

        if (rows.length > 0) {
            const user = rows[0];
            let parsedGenres = [];
            if (user.generi_preferiti !== null && user.generi_preferiti !== undefined) {
                try {
                    parsedGenres = JSON.parse(user.generi_preferiti);
                } catch (e) {
                    console.error("Errore nel parsing dei generi durante il recupero del profilo:", e);
                    parsedGenres = [];
                }
            }

            res.status(200).json({
                id: user.id,
                nome: user.nome,
                email: user.email,
                generi_preferiti: parsedGenres,
                mood_attuale: user.mood_attuale
            });
        } else {
            res.status(404).json({ error: 'Profilo utente non trovato nel DB locale.' });
        }
    } catch (error) {
        console.error('Errore nel recupero del profilo utente:', error);
        res.status(500).json({ error: 'Errore interno del server.' });
    }
});

// backend_structure.js

// ... (le tue importazioni, configurazioni e rotte esistenti) ...

app.post('/api/auth/refresh', async (req, res) => {
    try {
        const { refreshToken, email } = req.body; // Avrai bisogno del refresh token e dell'email dell'utente

        if (!refreshToken || !email) {
            return res.status(400).json({ error: 'Refresh token ed email sono richiesti.' });
        }

        const CLIENT_ID = process.env.COGNITO_CLIENT_ID;
        const CLIENT_SECRET = process.env.COGNITO_CLIENT_SECRET;

        console.log('CLIENT_ID letto:', CLIENT_ID); // Verifica che sia letto correttamente
        console.log('CLIENT_SECRET: ', CLIENT_SECRET);
        console.log('CLIENT_SECRET letto:', CLIENT_SECRET ? 'Presente' : 'Non Presente'); // Verifica se è definito

        console.log('HMAC input (email + CLIENT_ID):', email + CLIENT_ID);

        const hmac = crypto.createHmac('sha256', CLIENT_SECRET);
        hmac.update(email + CLIENT_ID);
        const secretHash = hmac.digest('base64');

        console.log('Calculated SECRET_HASH:', secretHash);

        const cognitoParams = {
            AuthFlow: 'REFRESH_TOKEN_AUTH', // Flusso di autenticazione per il refresh
            UserPoolId: process.env.COGNITO_USER_POOL_ID,
            ClientId: CLIENT_ID,
            AuthParameters: {
                REFRESH_TOKEN: refreshToken,
                USERNAME: email, // Cognito richiede l'username anche per il refresh
                SECRET_HASH: secretHash
            }
        };

        const result = await cognito.adminInitiateAuth(cognitoParams).promise();

        res.status(200).json({
            message: 'Token rinfrescati con successo!',
            AuthenticationResult: result.AuthenticationResult
        });

    } catch (error) {
        console.error('Errore durante il refresh del token:', error);
        if (error.code === 'NotAuthorizedException' || error.code === 'InvalidGrantException') {
            res.status(401).json({ error: 'Refresh token non valido o scaduto. Si prega di effettuare nuovamente il login.' });
        } else {
            res.status(500).json({ error: 'Errore interno del server durante il refresh del token.' });
        }
    }
});

// Aggiornare mood utente
// aggiorna il campo "current_mood"
app.put('/api/users/:id/mood', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { mood } = req.body;
    
    if (!mood) {
      return res.status(400).json({ error: 'Mood richiesto' });
    }
    
    const query = `
      UPDATE utenti SET mood_attuale = ?, data_creazione = NOW()
      WHERE id = ?
    `;
    
    const [result] = await pool.execute(query, [mood, id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Utente non trovato' });
    }
    
    // Recuperare l'utente aggiornato
    const [userRows] = await pool.execute(
      'SELECT id, mood_attuale FROM utenti WHERE id = ?',
      [id]
    );
    
    res.json({
      message: 'Mood aggiornato con successo',
      user: userRows[0]
    });
    
  } catch (error) {
    console.error('Errore aggiornamento mood:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Ottenere consigli musicali
// recupera generi preferiti e mood; trova canzoni inerenti; esclude canzoni già valutate negativamente
app.get('/api/recommendations/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const limit = parseInt(req.query.limit) || 10;
    
    // Recuperare preferenze utente
    const userQuery = `
      SELECT generi_preferiti, mood_attuale
      FROM utenti WHERE id = ?
    `;
    
    const [userRows] = await pool.execute(userQuery, [userId]);
    
    if (userRows.length === 0) {
      return res.status(404).json({ error: 'Utente non trovato' });
    }
    
    const user = userRows[0];
    //const genres = JSON.parse(user.generi_preferiti);
    let genres = [];
    const mood = user.mood_attuale;

    if (user.generi_preferiti !== null && user.generi_preferiti !== undefined) {
        try {
            // Tenta prima il parsing JSON se la stringa sembra un array JSON
            if (typeof user.generi_preferiti === 'string' &&
                user.generi_preferiti.startsWith('[') && user.generi_preferiti.endsWith(']')) {
                genres = JSON.parse(user.generi_preferiti);
            } else if (typeof user.generi_preferiti === 'string') {
                    // Se non è JSON valido ma è una stringa, prova a dividerla per virgole
                  genres = user.generi_preferiti.split(',').map(g => g.trim());
              } else if (Array.isArray(user.generi_preferiti)) {
                    // Se è già un array (ad esempio se il driver del DB lo converte automaticamente)
                  genres = user.generi_preferiti;
              }
            } catch (e) {
                console.error("Errore nel parsing dei generi per le raccomandazioni:", e);
                console.error("Valore generi_preferiti problematico:", user.generi_preferiti);
                // Fallback robusto: se tutto fallisce nel try, prova a dividere per virgole
                if (typeof user.generi_preferiti === 'string') {
                    genres = user.generi_preferiti.split(',').map(g => g.trim());
              } else {
                  genres = []; // Se non è una stringa, assegna un array vuoto
              }
          }
      }

      if (genres.length === 0) {
        return res.status(400).json({ error: 'Nessun genere preferito valido trovato per l\'utente.' });
      }
    
    // Creare placeholders per la query IN
    const genrePlaceholders = genres.map(() => '?').join(', ');

    console.log("--- DEBUG PLACEHOLDERS ---");
    console.log("Genres array:", genres);
    console.log("Genres length:", genres.length);
    console.log("genrePlaceholders:", genrePlaceholders);
    console.log("genrePlaceholders type:", typeof genrePlaceholders);
    console.log("------------------------");

    const recommendationQuery = `
        SELECT s.id, s.titolo, s.artista, s.genere, s.tag_mood, s.url_s3, s.durata, s.url_immagine_copertina, s.popolarita, s.data_creazione
        FROM canzoni s
        LEFT JOIN feedback_utente fu ON s.id = fu.id_canzone AND fu.id_utente = ?
        WHERE s.genere IN (${genrePlaceholders})
        AND (s.tag_mood IS NULL OR s.tag_mood = ?)
        AND (fu.voto_feedback IS NULL OR fu.voto_feedback >= 3)
        ORDER BY s.popolarita DESC, RAND()
        LIMIT ?
    `;

    console.log("QUERY DOPO INTERPOLAZIONE:", recommendationQuery);

    
    const queryParams = [parseInt(userId),...genres, mood, limit];
    
    console.log("--- DEBUGGING QUERY PARAMS ---");
    console.log("Genres:", genres, "Type:", typeof genres, "Length:", genres.length);
    console.log("Mood:", mood, "Type:", typeof mood);
    console.log("UserId:", userId, "Type:", typeof userId);
    console.log("UserId parsed:", parseInt(userId), "Type:", typeof parseInt(userId));
    console.log("Limit:", limit, "Type:", typeof limit);
    console.log("Full QueryParams Array:", queryParams);
    console.log("Generated query:", recommendationQuery);
    
    console.log("----------------------------");
    
    const [recommendations] = await pool.execute(recommendationQuery, queryParams);
    
    // Recuperare statistiche utente
    const statsQuery = `
      SELECT 
        COUNT(*) as total_rated,
        AVG(voto_feedback) as avg_rating,
        COUNT(CASE WHEN voto_feedback >= 4 THEN 1 END) as liked_songs
      FROM feedback_utente 
      WHERE id_utente = ?
    `;
    
    const [statsRows] = await pool.execute(statsQuery, [userId]);
    
    res.json({
      recommendations: recommendations,
      basedOn: {
        genres: genres,
        mood: mood
      },
      userStats: statsRows[0]
    });
    
  } catch (error) {
    console.error('Errore raccomandazioni:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Ottenere tutte le canzoni (con filtri opzionali)
// endpoint per browsing del catalogo
app.get('/api/songs', authenticateToken, async (req, res) => {
  try {
    const { genre, mood, search, limit = 20, offset = 0 } = req.query;
    
    let query = `
      SELECT s.id, s.titolo, s.artista, s.genere, s.tag_mood, s.url_s3, s.durata, s.url_immagine_copertina, s.popolarita, s.data_creazione
      FROM canzoni s
      WHERE 1=1
    `;
    
    const queryParams = [];
    
    // Filtro per genere
    if (genre) {
      query += ` AND s.genere = ?`;
      queryParams.push(genere);
    }
    
    // Filtro per mood
    if (mood) {
      query += ` AND FIND_IN_SET(?, s.tag_mood)`;
      queryParams.push(mood);
    }
    
    // Ricerca per titolo o artista
    if (search) {
      query += ` AND (s.titolo LIKE ? OR s.artista LIKE ?)`;
      queryParams.push(`%${search}%`, `%${search}%`);
    }
    
    query += ` ORDER BY s.popolarita DESC, s.data_creazione DESC LIMIT ? OFFSET ?`;
    queryParams.push(parseInt(limit), parseInt(offset));
    
    const [songs] = await pool.execute(query, queryParams);
    
    // Conteggio totale per paginazione
    let countQuery = `SELECT COUNT(*) as total FROM canzoni s WHERE 1=1`;
    const countParams = [];
    
    if (genre) {
      countQuery += ` AND s.genere = ?`;
      countParams.push(genre);
    }
    if (mood) {
      countQuery += ` AND FIND_IN_SET(?, s.tag_mood)`;
      countParams.push(mood);
    }
    if (search) {
      countQuery += ` AND (s.titolo LIKE ? OR s.artista LIKE ?)`;
      countParams.push(`%${search}%`, `%${search}%`);
    }
    
    const [countRows] = await pool.execute(countQuery, countParams);
    
    res.json({
      songs: songs,
      pagination: {
        total: countRows[0].total,
        limit: parseInt(limit),
        offset: parseInt(offset),
        hasMore: (parseInt(offset) + parseInt(limit)) < countRows[0].total
      }
    });
    
  } catch (error) {
    console.error('Errore recupero canzoni:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Ottenere URL presegnato per upload su S3
// genera URL presegnato per upload diretto su S3
app.post('/api/songs/upload-url', authenticateToken, async (req, res) => {
  try {
    const { fileName, fileType } = req.body;
    
    if (!fileName || !fileType) {
      return res.status(400).json({ error: 'Nome file e tipo file richiesti' });
    }
    
    const key = `songs/${Date.now()}-${fileName}`;
    
    const params = {
      Bucket: process.env.S3_BUCKET_NAME,
      Key: key,
      ContentType: fileType,
      Expires: 3600 // 1 ora
    };
    
    const signedUrl = s3.getSignedUrl('putObject', params);
    
    res.json({
      uploadUrl: signedUrl,
      key: key
    });
    
  } catch (error) {
    console.error('Errore generazione URL:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Salvare informazioni canzone dopo upload
// salva metadati della canzone nel DB
app.post('/api/songs', authenticateToken, async (req, res) => {
  try {
    const { title, artist, genre, moodTags, s3Key, duration, coverImageUrl } = req.body;
    
    if (!title || !artist || !genre || !s3Key) {
      return res.status(400).json({ error: 'Dati obbligatori mancanti' });
    }
    
    const query = `
      INSERT INTO canzoni (titolo, artista, genere, tag_mood, url_s3, durata, url_immagine_copertina, popolarita, data_creazione)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
    `;
    
    const s3Url = `https://${process.env.S3_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${s3Key}`;
    
    const [result] = await pool.execute(query, [
      title,
      artist,
      genre,
      JSON.stringify(moodTags || []),
      s3Url,
      duration || 0,
      coverImageUrl || null,
      0 // popularity iniziale
    ]);
    
    // Recuperare la canzone appena creata
    const [songRows] = await pool.execute(
      'SELECT id, titolo, artista, genere, tag_mood FROM canzoni WHERE id = ?',
      [result.insertId]
    );
    
    const song = songRows[0];
    song.mood_tags = JSON.parse(song.mood_tags);
    
    res.status(201).json({
      message: 'Canzone salvata con successo',
      song: song
    });
    
  } catch (error) {
    console.error('Errore salvataggio canzone:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Valutare una canzone
// permette di valutare una canzone (1-5 stelle)
app.post('/api/songs/:songId/rate', authenticateToken, async (req, res) => {
  try {
    const { songId } = req.params;
    const { rating } = req.body;
    const userId = req.user.id;
    
    if (!rating || rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'Rating deve essere tra 1 e 5' });
    }
    
    // Verificare che la canzone esista
    const [songCheck] = await pool.execute(
      'SELECT id FROM canzoni WHERE id = ?',
      [songId]
    );
    
    if (songCheck.length === 0) {
      return res.status(404).json({ error: 'Canzone non trovata' });
    }
    
    // MySQL: INSERT ... ON DUPLICATE KEY UPDATE
    const query = `
      INSERT INTO feedback_utente (id_utente, id_canzone, voto_feedback, data_creazione)
      VALUES (?, ?, ?, NOW(), NOW())
      ON DUPLICATE KEY UPDATE
      voto_feedback = VALUES(voto_feedback), data_aggiornamento = NOW()
    `;
    
    await pool.execute(query, [userId, songId, rating]);
    
    // Recuperare la valutazione salvata
    const [ratingRows] = await pool.execute(
      'SELECT voto_feedback, data_creazione FROM feedback_utente WHERE id_utente = ? AND id_canzone = ?',
      [userId, songId]
    );
    
    // Aggiornare la popolarità della canzone basata sui rating
    const updatePopularityQuery = `
      UPDATE canzoni SET popolarita = (
        SELECT COALESCE(AVG(voto_feedback) * COUNT(voto_feedback), 0)
        FROM feedback_utente WHERE id_canzone = ?
      ) WHERE id = ?
    `;
    
    await pool.execute(updatePopularityQuery, [songId, songId]);
    
    res.json({
      message: 'Valutazione salvata con successo',
      rating: ratingRows[0]
    });
    
  } catch (error) {
    console.error('Errore valutazione:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Ottenere valutazioni utente
// recupera tutte le valutazioni di un utente
app.get('/api/users/:userId/ratings', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const { limit = 20, offset = 0 } = req.query;
    
    const query = `
      SELECT 
        ur.voto_feedback, ur.data_creazione, ur.data_aggiornamento,
        s.id as canzone_id, s.titolo, s.artista, s.genere, s.url_immagine_copertina
      FROM feedback_utente ur
      JOIN canzoni s ON ur.id_canzone = s.id
      WHERE ur.id_utente = ?
      ORDER BY ur.data_creazione DESC
      LIMIT ? OFFSET ?
    `;
    
    const [ratings] = await pool.execute(query, [userId, parseInt(limit), parseInt(offset)]);
    
    res.json({
      ratings: ratings,
      pagination: {
        limit: parseInt(limit),
        offset: parseInt(offset)
      }
    });
    
  } catch (error) {
    console.error('Errore recupero valutazioni:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Ottenere statistiche generali della piattaforma
// endpoint per dashboard admin
app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    const statsQuery = `
      SELECT 
        (SELECT COUNT(*) FROM utenti) as total_users,
        (SELECT COUNT(*) FROM canzoni) as total_songs,
        (SELECT COUNT(*) FROM feedback_utente) as total_ratings,
        (SELECT AVG(rating) FROM feedback_utente) as avg_rating,
        (SELECT COUNT(DISTINCT id_utente) FROM feedback_utente) as active_users
    `;
    
    const [stats] = await pool.execute(statsQuery);
    
    // Top generi
    const genreQuery = `
      SELECT genere, COUNT(*) as count
      FROM canzoni
      GROUP BY genere
      ORDER BY count DESC
      LIMIT 10
    `;
    
    const [genres] = await pool.execute(genreQuery);
    
    res.json({
      stats: stats[0],
      topGenres: genres
    });
    
  } catch (error) {
    console.error('Errore statistiche:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Gestione errori globale
app.use((error, req, res, next) => {
  console.error('Errore non gestito:', error);
  res.status(500).json({ error: 'Errore interno del server' });
});

// Gestione route non trovate
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint non trovato' });
});

// Avvio server
const server = app.listen(port, () => {
  console.log(`Server in ascolto sulla porta ${port}`);
});

// Gestione shutdown graceful
process.on('SIGTERM', () => {
  console.log('Ricevuto SIGTERM, chiudendo server...');
  server.close(() => {
    console.log('Server chiuso');
    pool.end();
  });
});

process.on('SIGINT', () => {
  console.log('Ricevuto SIGINT, chiudendo server...');
  server.close(() => {
    console.log('Server chiuso');
    pool.end();
  });
});

module.exports = app;