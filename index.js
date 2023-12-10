const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();
const http = require("http");
const server = http.createServer(app);
const nodemailer = require("nodemailer");
const cors = require("cors");
const multer = require("multer");
require("dotenv").config();
const crypto = require("crypto");
const { v4: uuidv4 } = require('uuid');
const MAX_FAILED_LOGIN_ATTEMPTS = 5;
const BLOCKED_DURATION_SECONDS = 30;
app.use(
  cors({
    origin: "*",
  })
);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
// Configuration de l'upload de fichier avec Multer
app.use("/uploads", express.static("uploads"));
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "./uploads/");
  },
  filename: function (req, file, cb) {
    crypto.randomBytes(16, (err, hash) => {
      if (err) return cb(err);
      const fileName = `${hash.toString("hex")}-${file.originalname}`;
      cb(null, fileName);
    });
  },
});
const upload = multer({ storage: storage });

const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "password",
  database: "windflow",
});

connection.connect((err) => {
  if (err) {
    console.log(`Error connecting to database: ${err}`);
    return;
  }

  console.log('Connected to database successfully!');
});
const transporter = nodemailer.createTransport({
  host: "0.0.0.0",
  port: 1025,
  secure: false,
  auth: {
    user: "",
    pass: "",
  },
  tls: {
    rejectUnauthorized: false
  },
});
function string_to_slug(str) {
  str = str.replace(/^\s+|\s+$/g, ""); // trim
  str = str.toLowerCase();

  // remove accents, swap ñ for n, etc
  var from = "àáäâèéëêìíïîòóöôùúüûñç·/_,:;";
  var to = "aaaaeeeeiiiioooouuuunc------";
  for (var i = 0, l = from.length; i < l; i++) {
    str = str.replace(new RegExp(from.charAt(i), "g"), to.charAt(i));
  }

  str = str
    .replace(/[^a-z0-9 -]/g, "") // remove invalid chars
    .replace(/\s+/g, "-") // collapse whitespace and replace by -
    .replace(/-+/g, "-"); // collapse dashes

  return str;
}

const permit = (...permittedRoles) => {
  // return a middleware
  return (request, response, next) => {
    const { user } = request

    if (user && permittedRoles.includes(user.role)) {
      next(); // role is allowed, so continue on the next middleware
    } else {
      response.status(403).json({ message: "Forbidden" }); // user is forbidden
    }
  }
}
// Middleware pour vérifier si l'utilisateur est suspendu
const checkIfSuspended = (req, res, next) => {
  const userId = req.user.id;

  connection.execute(
    "SELECT suspended_until FROM users WHERE id = ?",
    [userId],
    (error, results, fields) => {
      if (error) {
        console.error(error);
        res.status(500).json({ error: "Server error" });
      } else if (results.length === 0) {
        res.status(401).json({ error: "User not found" });
      } else {
        const suspendedUntil = results[0].suspended_until;
        if (suspendedUntil && new Date(suspendedUntil) > new Date()) {
          res.status(403).json({ error: "User is suspended" });
        } else {
          next();
        }
      }
    }
  );
};


function generateRandomCode() {
  // Générer un nombre aléatoire entre 0 et 9999
  const code = Math.floor(Math.random() * 10000);

  // Ajouter des zéros au début du code pour avoir toujours 4 chiffres
  return code.toString().padStart(4, "0");
}

function findDifferenceIndex(text1, text2) {
  const minLength = Math.min(text1.length, text2.length);
  let index = 0;

  while (index < minLength && text1[index] === text2[index]) {
    index++;
  }

  if (index === minLength) {
    return -1;
  }

  return index;
}

const authenticateUser = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null)
    return res.status(401).json({ message: "Authorization header missing" });
  // Vérifier que le token est valide

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Token invalide" });
    req.user = user;
    next();
  });
};

// Endpoint pour suspendre un utilisateur pour une certaine durée
app.post("/user/:id/suspend", (req, res) => {
  const userId = req.params.id;
  const { suspendedUntil } = req.body;

  connection.execute(
    "UPDATE users SET suspended_until = ? WHERE id = ?",
    [suspendedUntil, userId],
    (error, results, fields) => {
      if (error) {
        console.error(error);
        res.status(500).json({ error: "Server error" });
      } else if (results.affectedRows === 0) {
        res.status(404).json({ error: "User not found" });
      } else {
        res.status(200).json({ message: "User suspended successfully" });
      }
    }
  );
});

app.post("/register", (req, res) => {
  const { username, email, password, confirmPassword } = req.body;
  const photo = "https://ui-avatars.com/api/?name=" + username;
  const verificationCode = generateRandomCode();

  // Vérifier si l'utilisateur existe déjà
  connection.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    (error, results, fields) => {
      if (error) {
        console.error(error);
        res.status(500).json({ message: "Server error" });
      } else if (results.length > 0) {
        // L'utilisateur existe déjà, retourner une erreur
        res
          .status(409)
          .json({ message: "User with this email already exists", code: 409 });
      } else if (password !== confirmPassword) {
        // Les mots de passe ne correspondent pas, retourner une erreur
        res.status(400).json({ message: "Passwords don't match", code: 400 });
      } else {
        // L'utilisateur n'existe pas encore, hash le mot de passe
        bcrypt.hash(password, 10, (err, hash) => {
          if (err) {
            console.error(err);
            res.status(500).json({ message: "Server error", code: 500 });
          } else {
            // Ajouter l'utilisateur à la base de données
            const expirationDate = new Date(); // Récupérer la date actuelle
            //  expirationDate.setMinutes(expirationDate.getMinutes() + 10); // Ajouter 10 minutes à la date actuelle
            expirationDate.setMinutes(expirationDate.getMinutes() + 10); // Ajouter 10 minutes à la date actuelle

            connection.query(
              "INSERT INTO users (name, email, photo, password, is_verified, verification_token,verification_token_expires_at) VALUES (?, ?, ?, ?, ?, ?,?)",
              [
                username,
                email,
                photo,
                hash,
                false,
                verificationCode,
                expirationDate,
              ],
              (error, results, fields) => {
                if (error) {
                  console.error(error);
                  res.status(500).json({ message: "Server error", code: 500 });
                } else {
                  const mailOptions = {
                    to: email,
                    subject: "Vérification de compte",
                    text: `Votre code de vérification est : ${verificationCode}`,
                  };
                  transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                      console.error(error);
                      res
                        .status(500)
                        .json({ message: "Server error", code: 500 });
                    } else {
                      res.status(200).json({
                        message: `Un email de vérification a été envoyé à l'adresse ${email}. Veuillez cliquer sur le lien dans l'email pour vérifier votre compte.`,
                        code: 200,
                      });
                    }
                  });
                }
              }
            );
          }
        });
      }
    }
  );
});
app.post("/verify", (req, res) => {
  const { code, password } = req.body;
  console.log("code", code);
  // Vérifier si le code de vérification est correct
  connection.query(
    "SELECT * FROM users WHERE verification_token = ?  AND verification_token_expires_at > NOW()",
    [code],
    (error, results) => {
      if (error) {
        console.error("error verification token", error);
        res.status(500).json({ error: "Server error" });
      } else if (results.length === 0) {
        // Le code de vérification est incorrect
        res.status(400).json({ message: "Code de vérification incorrect" });
      } else {
        // Mettre à jour le champ is_verified pour l'utilisateur
        const user = results[0];
        const now = new Date();

        if (user.verification_token_expires_at < now) {
          // Générer un nouveau code d'activation et le stocker dans la base de données
          const newCode = generateRandomCode(4);
          connection.query(
            "UPDATE users SET verification_token = ?, verification_token_expires_at = DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE id = ?",
            [newCode, user.id],
            (error, results, fields) => {
              if (error) throw error;

              // Envoyer le nouveau code de  à l'utilisateur par e-mail
              const mailOptions = {
                to: email,
                subject: "Vérification de compte",
                text: `Votre code de vérification est : ${newCode}`,
              };
              transporter.sendMail(mailOptions, (error, info) => {
                if (error) throw error;
                //      console.log('Code de verification envoyé :', newCode);
              });
              return res.status(404).json({
                message:
                  "The verification has expired. A new code has been sent to your email.",
              });
            }
          );
        }
        connection.query(
          "UPDATE users SET is_verified = true, verification_token_expires_at= null WHERE id = ?",
          [user.id],
          (error, results) => {
            if (error) {
              console.error("is_verified users", error);
              res.status(500).json({ message: "Server error" });
            } else {
              // Comparer le mot de passe entré avec le mot de passe stocké hashé
              bcrypt.compare(password, user.password, (err, result) => {
                if (err) {
                  console.error("error compare mdp", err);
                  res.status(500).send("Erreur serveur");
                }
                if (!result && !user.is_blocked) {
                  res.status(401).json({
                    message: "L'email ou le mot de passe est incorrect.",
                  });
                  // Incrémenter le compteur de tentatives de connexion infructueuses
                  connection.query(
                    "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?",
                    user.id,
                    (error, results, fields) => {
                      console.log("error failed_login_attempts", error);
                      if (error) res.status(500).send("Erreur serveur");

                      // Si le nombre de tentatives de connexion infructueuses dépasse le seuil, bloquer le compte
                      if (
                        user.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS
                      ) {
                        connection.query(
                          "UPDATE users SET is_blocked = true WHERE id = ?",
                          user.id,
                          (error, results, fields) => {
                            console.log("is_blocked", error);
                            if (error) res.status(500).send("Erreur serveur");
                          }
                        );
                      }
                    }
                  );
                  return;
                }
                if (user.is_blocked) {
                  res.status(403).json({ message: "Ce compte est bloqué." });
                  return;
                } else if (
                  user.suspended_until &&
                  new Date(user.suspended_until) > new Date()
                ) {
                  res.status(403).json({
                    message:
                      "Account suspended until " +
                      new Date(user.suspended_until).toLocaleString(),
                  });
                } else {
                  connection.query(
                    "UPDATE users SET failed_login_attempts = 0 WHERE id = ?",
                    user.id,
                    (error, results, fields) => {
                      console.error("failed_login_attempts", error);
                      if (error) res.status(500).send("Erreur serveur");
                    }
                  );
                  connection.query(
                    "UPDATE users SET is_blocked = false WHERE id = ?",
                    user.id,
                    (error, results, fields) => {
                      console.log("error is_blocked", error);
                      if (error) res.status(500).send("Erreur serveur");
                    }
                  );
                  // Générer un token JWT valide avec les informations d'identification de l'utilisateur
                  const accessToken = jwt.sign(
                    {
                      id: user.id,
                      email: user.email,
                      username: user.name,
                      photo: user.photo,
                    },
                    process.env.JWT_SECRET,
                    { expiresIn: "10s" }
                  );
                  const refreshToken = jwt.sign(
                    {
                      id: user.id,
                      email: user.email,
                      username: user.name,
                      photo: user.photo,
                    },
                    process.env.REFRESH_TOKEN_SECRET,
                    { expiresIn: "7d" }
                  );
                  connection.query(
                    "UPDATE users SET refresh_token = ? WHERE id = ?",
                    [refreshToken, user.id],
                    (error, results, fields) => {
                      console.log("error refresh token", error);
                      if (error) res.status(500).send("Erreur serveur");
                    }
                  );
                  res.status(200).json({
                    accessToken,
                    refreshToken,
                    isVerified: user.is_verified,
                  });
                }
              });
            }
          }
        );
      }
    }
  );
});
app.post("/regenerate/verify/code", (req, res) => {
  const email = req.body.email;

  // Vérifier si l'utilisateur existe
  connection.query(
    "SELECT * FROM users WHERE email = ?",
    email,
    (error, results) => {
      if (error) throw error;

      if (results.length === 0) {
        // L'utilisateur n'existe pas
        return res.status(404).json({ message: "L'utilisateur n'existe pas" });
      }
      const user = results[0];
      // Générer un nouveau code de réinitialisation
      const newCode = generateRandomCode(); // Générer un code aléatoire de 4 chiffres
      const expirationDate = new Date(); // Récupérer la date actuelle
      //  expirationDate.setMinutes(expirationDate.getMinutes() + 10); // Ajouter 10 minutes à la date actuelle
      expirationDate.setMinutes(expirationDate.getMinutes() + 10); // Ajouter 10 minutes à la date actuelle

      // Insérer le nouveau code de réinitialisation dans la base de données
      connection.query(
        "UPDATE users SET verification_token = ?, verification_token_expires_at = DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE id = ?",
        [newCode, user.id],
        (error, results, fields) => {
          if (error) throw error;

          // Envoyer le nouveau code de  à l'utilisateur par e-mail
          const mailOptions = {
            to: email,
            subject: "Vérification de compte",
            text: `Votre code de vérification est : ${newCode}`,
          };
          transporter.sendMail(mailOptions, (error, info) => {
            if (error) throw error;
            //      console.log('Code de verification envoyé :', newCode);
          });
          return res.status(404).json({
            message: "A new code has been sent to your email.",
          });
        }
      );
    }
  );
});
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  console.log('ici', req.body);
  // Vérifier si l'utilisateur existe dans la base de données
  connection.query(
    "SELECT * FROM users WHERE email = ?",
    email,
    (error, results, fields) => {
      if (error) throw error;

      if (results.length === 0) {
        res
          .status(401)
          .json({ message: "L'email ou le mot de passe est incorrect." });
      } else {
        const user = results[0];

        // Comparer le mot de passe entré avec le mot de passe stocké hashé
        bcrypt.compare(password, user.password, (err, result) => {
          if (err) res.status(500).send("Erreur serveur");
          if (!result && !user.is_blocked) {
            // Incrémenter le compteur de tentatives de connexion infructueuses
            connection.query(
              "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?",
              user.id,
              (error, results, fields) => {
                if (error) res.status(500).send("Erreur serveur");

                // Si le nombre de tentatives de connexion infructueuses dépasse le seuil, bloquer le compte temporairement
                if (user.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS) {
                  const blockedUntil = new Date(
                    Date.now() + BLOCKED_DURATION_SECONDS * 1000
                  );
                  blockedUntil.setHours(
                    blockedUntil.getHours() -
                    new Date().getTimezoneOffset() / 60
                  );
                  const blockedUntilString = blockedUntil
                    .toISOString()
                    .slice(0, 19)
                    .replace("T", " ");
                  connection.query(
                    "UPDATE users SET is_blocked = true, blocked_until = ? WHERE id = ?",
                    [blockedUntilString, user.id],
                    (error, results, fields) => {
                      if (error) res.status(500).send("Erreur serveur");
                    }
                  );

                  res.status(401).json({
                    message: `Trop de tentatives de connexion infructueuses. Ce compte est bloqué temporairement pendant 30 secondes.`,
                    blockedUntil: blockedUntil,
                  });
                  return;
                }

                res.status(401).json({
                  message: "L'email ou le mot de passe est incorrect.",
                });
              }
            );
            return;
          }
          if (user.is_blocked) {
            // Vérifier si le compte est bloqué temporairement
            console.log(new Date(user.blocked_until), new Date());
            if (new Date(user.blocked_until) > new Date()) {
              const timeLeft = Math.floor(
                (new Date(user.blocked_until) - new Date()) / 1000
              );
              res.status(401).json({
                message:
                  "Le compte est bloqué temporairement pour " +
                  timeLeft +
                  " secondes.",
                blockedUntil: timeLeft,
              });
            } else {
              // Débloquer le compte si le temps de blocage est écoulé
              connection.query(
                "UPDATE users SET is_blocked = false WHERE id = ?",
                user.id,
                (error, results, fields) => {
                  if (error) res.status(500).send("Erreur serveur");
                }
              );
              res
                .status(401)
                .json({ message: "L'email ou le mot de passe est incorrect." });
            }
            return;
          } else if (
            user.suspended_until &&
            new Date(user.suspended_until) > new Date()
          ) {
            res.status(403).json({
              message:
                "Account suspended until " +
                new Date(user.suspended_until).toLocaleString(),
            });
          } else {
            connection.query(
              "UPDATE users SET failed_login_attempts = 0 WHERE id = ?",
              user.id,
              (error, results, fields) => {
                if (error) res.status(500).send("Erreur serveur");
              }
            );
            connection.query(
              "UPDATE users SET is_blocked = false WHERE id = ?",
              user.id,
              (error, results, fields) => {
                if (error) res.status(500).send("Erreur serveur");
              }
            );
            // Générer un token JWT valide avec les informations d'identification de l'utilisateur
            const accessToken = jwt.sign(
              {
                id: user.id,
                email: user.email,
                username: user.name,
                photo: user.photo,
              },
              process.env.JWT_SECRET,
              { expiresIn: "10s" }
            );
            const refreshToken = jwt.sign(
              {
                id: user.id,
                email: user.email,
                username: user.name,
                photo: user.photo,
              },
              process.env.REFRESH_TOKEN_SECRET,
              { expiresIn: "8d" }
            );
            connection.query(
              "UPDATE users SET refresh_token = ? WHERE id = ?",
              [refreshToken, user.id],
              (error, results, fields) => {
                if (error) res.status(500).send("Erreur serveur");
              }
            );
            res.status(200).json({
              user: {
                id: user.id,
                email: user.email,
                name: user.name,
                photo: user.photo,
              },
              accessToken,
              refreshToken,
              isVerified: user.is_verified,
            });
          }
        });
      }
    }
  );
});

app.post("/refresh-token", (req, res) => {
  const { refreshToken } = req.body;
  // console.log("call refresh  token api", refreshToken);
  // Vérifier si le refresh token est valide
  console.log(req.body);
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }

    // Vérifier si le refresh token correspond à l'utilisateur en base de données
    connection.query(
      "SELECT * FROM users WHERE id = ? AND refresh_token = ?",
      [user.id, refreshToken],
      (error, results, fields) => {
        if (error) throw error;
        if (!results) {
          return res.sendStatus(403);
        } else {
          // Générer un nouveau token JWT valide avec les informations d'identification de l'utilisateur
          const token = jwt.sign(
            {
              id: user.id,
              email: user.email,
              username: user.username,
              photo: user.photo,
            },
            process.env.JWT_SECRET,
            { expiresIn: "1d" }
          );
          res.status(200).json({ token });
        }
      }
    );
  });
});

app.post("/password/reset", (req, res) => {
  const email = req.body.email;

  // Vérifier si l'utilisateur existe
  connection.query(
    "SELECT * FROM users WHERE email = ?",
    email,
    (error, results) => {
      if (error) throw error;

      if (results.length === 0) {
        // L'utilisateur n'existe pas
        return res.status(404).json({ message: "L'utilisateur n'existe pas" });
      }

      // Générer un nouveau code de réinitialisation
      const code = generateRandomCode(); // Générer un code aléatoire de 4 chiffres
      const expirationDate = new Date(); // Récupérer la date actuelle
      //  expirationDate.setMinutes(expirationDate.getMinutes() + 10); // Ajouter 10 minutes à la date actuelle
      expirationDate.setMinutes(expirationDate.getMinutes() + 10); // Ajouter 10 minutes à la date actuelle

      // Insérer le nouveau code de réinitialisation dans la base de données
      connection.query(
        "INSERT INTO password_reset_tokens SET ?",
        { email, code, expires_at: expirationDate },
        (error, results) => {
          if (error) throw error;

          // Envoyer le code de réinitialisation par e-mail
          const mailOptions = {
            to: email,
            subject: "Réinitialisation de mot de passe",
            text: `Votre code de réinitialisation de mot de passe est : ${code}`,
          };
          transporter.sendMail(mailOptions, (error, info) => {
            if (error) throw error;
            //console.log('Code de réinitialisation envoyé :', code);
            res.status(200).json({
              message:
                "Un code de réinitialisation a été envoyé à votre adresse e-mail",
            });
          });
        }
      );
    }
  );
});
app.post("/password/reset/verify", (req, res) => {
  const email = req.body.email;
  const code = req.body.code;

  // Vérifier si le code de réinitialisation est valide
  connection.query(
    "SELECT * FROM password_reset_tokens WHERE email = ? AND code = ? AND expires_at > NOW()",
    [email, code],
    (error, results) => {
      if (error) throw error;

      if (results.length === 0) {
        // Le code de réinitialisation n'est pas valide
        return res
          .status(400)
          .json({ message: "Le code de réinitialisation n'est pas valide" });
      }

      // Le code de réinitialisation est valide
      res
        .status(200)
        .json({ message: "Le code de réinitialisation est valide" });
    }
  );
});
app.post("/password/new", (req, res) => {
  const email = req.body.email;
  const code = req.body.code;
  const newPassword = req.body.newPassword;
  console.log(req.body);
  connection.query(
    "SELECT * FROM password_reset_tokens WHERE email = ? AND code = ?",
    [email, code],
    (error, results, fields) => {
      if (error) throw error;

      if (results.length === 0) {
        return res.status(404).json({ message: "Invalid code." });
      }

      const reset = results[0];
      const now = new Date();

      if (reset.expires_at < now) {
        // Générer un nouveau code de réinitialisation et le stocker dans la base de données
        const newCode = generateRandomCode(4);
        connection.query(
          "UPDATE password_reset_tokens SET code = ?, expires_at = DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE id = ?",
          [newCode, reset.id],
          (error, results, fields) => {
            if (error) throw error;

            // Envoyer le nouveau code de réinitialisation à l'utilisateur par e-mail
            const mailOptions = {
              to: email,
              subject: "Réinitialisation de mot de passe",
              text: `Votre code de réinitialisation de mot de passe est : ${newCode}`,
            };
            transporter.sendMail(mailOptions, (error, info) => {
              if (error) throw error;
              //      console.log('Code de réinitialisation envoyé :', newCode);
            });
            return res.status(404).json({
              message:
                "The code has expired. A new code has been sent to your email.",
            });
          }
        );
      }

      // Mettre à jour le mot de passe de l'utilisateur
      bcrypt.hash(newPassword, 10, (err, hash) => {
        if (err) throw err;

        connection.query(
          "UPDATE users SET password = ? WHERE email = ?",
          [hash, email],
          (error, results, fields) => {
            if (error) throw error;

            // Supprimer le code de réinitialisation de la base de données
            connection.query(
              "DELETE FROM password_reset_tokens WHERE id = ?",
              [reset.id],
              (error, results, fields) => {
                if (error) throw error;

                return res
                  .status(200)
                  .json({ message: "Your password has been reset." });
              }
            );
          }
        );
      });
    }
  );
});
// Bloquer un utilisateur
app.post("/user/:id/block", (req, res) => {
  const userId = req.params.id;

  connection.execute(
    "UPDATE users SET is_blocked = ? WHERE id = ?",
    [true, userId],
    (error, results, fields) => {
      if (error) {
        console.error(error);
        res.status(500).json({ error: "Server error" });
      } else if (results.affectedRows === 0) {
        res.status(404).json({ error: "User not found" });
      } else {
        res.status(200).json({ message: "User blocked successfully" });
      }
    }
  );
});

// Débloquer un utilisateur
app.post("/user/:id/unblock", (req, res) => {
  const userId = req.params.id;

  connection.execute(
    "UPDATE users SET is_blocked = ? WHERE id = ?",
    [false, userId],
    (error, results, fields) => {
      if (error) {
        console.error(error);
        res.status(500).json({ error: "Server error" });
      } else if (results.affectedRows === 0) {
        res.status(404).json({ error: "User not found" });
      } else {
        res.status(200).json({ message: "User unblocked successfully" });
      }
    }
  );
});

app.put("/users/:id", authenticateUser, async (req, res) => {
  const { id } = req.params;
  const { name, email, password } = req.body;

  // Vérifier que l'utilisateur est autorisé à modifier le compte
  if (req.user_id !== parseInt(id)) {
    return res.status(403).json({ message: "Forbidden" });
  }

  // Mettre à jour le compte de l'utilisateur dans la base de données
  try {
    await connection.query(
      "UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?",
      [name, email, password, id]
    );
    res.status(204).send();
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Mettre à jour la photo de profil de l'utilisateur
app.put(
  "/profilePicture",
  authenticateUser,
  upload.single("photo"),
  function (req, res) {
    // Vérifier que l'utilisateur est connecté
    if (!req.user.id) {
      return res.status(401).json({
        message: "Vous devez être connecté pour effectuer cette action.",
      });
    }

    // Vérifier que la photo a été téléchargée avec succès
    if (!req.file) {
      return res
        .status(400)
        .json({ message: "Vous devez télécharger une photo." });
    }

    // Mettre à jour la photo de profil de l'utilisateur dans la base de données
    const userId = req.user.id;
    //console.log("userId", userId);
    const photoUrl =
      req.protocol + "://" + req.get("host") + "/" + req.file.path;
    //console.log(photoUrl);
    const sql = "UPDATE users SET photo = ? WHERE id = ?";
    connection.query(sql, [photoUrl, userId], function (err, result) {
      //console.log("result", result);
      if (err) {
        return res.status(500).json({
          message:
            "Une erreur est survenue lors de la mise à jour de la photo de profil.",
        });
      }
      return res.status(200).json({
        photoUrl: photoUrl,
        message: "La photo de profil a été mise à jour avec succès.",
      });
    });
  }
);
let validTokens = [];
function generateToken(filename) {
  const token = Math.random().toString(36).substr(2);
  const expiration = Date.now() + 60 * 60 * 1000;
  validTokens.push({ token, filename, expiration });
  return token;
}
app.get('/generate-access/:filename', (req, res) => {
  const filename = req.params.filename;
  const token = generateToken(filename);
  const accessURL = `/temp-mp3/${token}`;

  res.send(`Lien d'accès temporaire : <a href="${accessURL}">${accessURL}</a>`);
});
app.post('/projects', authenticateUser, (req, res) => {
  const { name, description, user_id } = req.body;
  if (!req.user.id) {
    return res.status(401).json({
      message: "Vous devez être connecté pour effectuer cette action.",
    });
  }
  const id = uuidv4();
  const created_at = new Date();
  connection.query(
    'INSERT INTO projects (id, name, description, user_id, created_at) VALUES (?, ?, ?, ?, ?)',
    [id, name, description, req.user.id, created_at],
    (err, results) => {
      if (err) {
        console.error('Erreur lors de la création du projet : ' + err.stack);
        res.status(500).send('Erreur lors de la création du projet.');
        return;
      }
      res.status(201).json({ id, name, description, user_id: req.user.id, created_at });
    }
  );
});
app.get('/projects', authenticateUser, (req, res) => {
  if (!req.user.id) {
    return res.status(401).json({
      message: "Vous devez être connecté pour effectuer cette action.",
    });
  }
  connection.query('SELECT * FROM projects', (err, results) => {
    if (err) {
      console.error('Erreur lors de la récupération des projets : ' + err.stack);
      res.status(500).send('Erreur lors de la récupération des projets.');
      return;
    }

    res.status(200).json(results);
  });
});
app.put('/projects/:id', (req, res) => {
  const projectId = req.params.id;

  const { name, description, user_id } = req.body;
  if (!req.user.id) {
    return res.status(401).json({
      message: "Vous devez être connecté pour effectuer cette action.",
    });
  }
  connection.query(
    'UPDATE projects SET name=?, description=?, user_id=? WHERE id=?',
    [name, description, user_id, projectId],
    (err, results) => {
      if (err) {
        console.error('Erreur lors de la mise à jour du projet : ' + err.stack);
        res.status(500).send('Erreur lors de la mise à jour du projet.');
        return;
      }

      if (results.affectedRows === 0) {
        res.status(404).send('Projet non trouvé.');
        return;
      }
      res.status(200).json({ id: projectId, name, description, user_id });
    }
  );
});
app.delete('/projects/:id', authenticateUser, (req, res) => {
  const projectId = req.params.id;
  if (!req.user.id) {
    return res.status(401).json({
      message: "Vous devez être connecté pour effectuer cette action.",
    });
  }
  connection.query('DELETE FROM projects WHERE id=?', [projectId], (err, results) => {
    if (err) {
      console.error('Erreur lors de la suppression du projet : ' + err.stack);
      res.status(500).send('Erreur lors de la suppression du projet.');
      return;
    }

    if (results.affectedRows === 0) {
      res.status(404).send('Projet non trouvé.');
      return;
    }

    res.status(204).end();
  });
});
app.get("/projects/:id", (req, res) => {
  const projectId = req.params.id;
  connection.query("SELECT * FROM projects WHERE id = ?", projectId, (err, projects) => {
    if (err) {
      return res.status(500).send(err.message);
    }
    if (!projects.length) {
      return res.status(404).send("Chanson non trouvée");
    }
    let project = projects[0];
    if (project) {
      connection.query(
        `SELECT * FROM pages WHERE project_id = ?`,
        [project.id],
        function (err, pages) {
          if (err) {
            console.error("Error retrieving pages:", err);
            return res.status(500).send(err.message);
          } else {
            if (pages.length > 0) {
              project = { ...project, pages: pages };
            }
            res.status(200).json(project);
          }
        }
      );
    }
  });
});



app.post('/pages', authenticateUser, (req, res) => {
  const { id, name, description, tags, blocks_id, blocks, projectId } = req.body;
  console.log('body', req.body);
  if (!req.user.id) {
    return res.status(401).json({
      message: "Vous devez être connecté pour effectuer cette action.",
    });
  }
  const created_at = new Date();
  connection.query(
    'INSERT INTO pages (name, description,tags,blocks,blocks_id, project_id, page_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?,?)',
    [name, description, tags, blocks, blocks_id, projectId, id, created_at],
    (err, results) => {
      if (err) {
        console.error('Erreur lors de la création de page : ' + err.stack);
        res.status(500).send('Erreur lors de la création de page.');
        return;
      }
      res.status(201).json({ id, name, description, tags, blocks, projectId, created_at });
    }
  );
});


app.put('/pages/:id', (req, res) => {
  const pageId = req.params.id;

  const { description, blocks } = req.body;

  connection.query(
    'UPDATE pages SET blocks=? WHERE page_id=?',
    [blocks, pageId],
    (err, results) => {
      if (err) {
        console.error('Erreur lors de la mise à jour du page : ' + err.stack);
        res.status(500).send('Erreur lors de la mise à jour du page.');
        return;
      }

      if (results.affectedRows === 0) {
        res.status(404).send('Page non trouvé.');
        return;
      }
      res.status(200).json({ blocks });
    }
  );
});
app.delete('/pages/:id', authenticateUser, (req, res) => {
  const pageId = req.params.id;

  connection.query('DELETE FROM pages WHERE page_id=?', [pageId], (err, results) => {
    if (err) {
      console.error('Erreur lors de la suppression du projet : ' + err.stack);
      res.status(500).send('Erreur lors de la suppression du projet.');
      return;
    }

    if (results.affectedRows === 0) {
      res.status(404).send('Projet non trouvé.');
      return;
    }

    res.status(204).end();
  });
});

app.post('/category-kits', authenticateUser, (req, res) => {
  const { name, description } = req.body;
  if (!req.user.id) {
    return res.status(401).json({
      message: "Vous devez être connecté pour effectuer cette action.",
    });
  }
  const id = uuidv4();
  const created_at = new Date();
  connection.query(
    'INSERT INTO category_kits (category_kit_id, name, description, user_id, created_at) VALUES (?, ?, ?, ?, ?)',
    [id, name, description, req.user.id, created_at],
    (err, results) => {
      if (err) {
        console.error('Erreur lors de la création du category de kits: ' + err.stack);
        res.status(500).send('Erreur lors de la création du category de kits.');
        return;
      }
      res.status(201).json({ id, name, description, user_id: req.user.id, created_at });
    }
  );
});
app.get("/category-kits", (req, res) => {
  let data = [];
  connection.query(
    "SELECT * FROM category_kits",
    [],
    (error, results) => {
      if (error) {
        return res.status(500).send(err.message);
      }
      if (!results.length) {
        return res.status(404).send("Chanson non trouvée");
      }
      const libraryPromises = results.map((el, index) => {
        data[index] = { ...el };
        return new Promise((resolve, reject) => {
          connection.query(
            `SELECT * from libraries WHERE category_kit_id = ?`,
            [el.category_kit_id],
            function (err, library) {
              if (err) {
                reject(err);
              } else {
                console.log('library', library.length);
                if (library.length > 0) {
                  let tpls = [];
                  library.forEach(lb => {
                    let templ = JSON.parse(lb.templates);
                  
                    tpls.push({ content: templ, id: lb.library_id, name: lb.name, image:lb.image, description: lb.description });
                    delete lb.image;
                  })
                  console.log(tpls.length);
                  data[index].json = {
                    templates: [...tpls]
                  };
                }

                resolve();
              }
            }
          );
        });
      });
      Promise.all(libraryPromises)
        .then(() => {
          res.send(data);
        })
        .catch((err) => {
          console.error(err);
        });

    });
});

app.post('/library', authenticateUser, (req, res) => {
  const { name,image, description, templates, categoryId } = req.body;
  if (!req.user.id) {
    return res.status(401).json({
      message: "Vous devez être connecté pour effectuer cette action.",
    });
  }
  const id = uuidv4();
  const created_at = new Date();
  connection.query(
    'INSERT INTO libraries (library_id, name, image, description, user_id,templates,	category_kit_id, created_at) VALUES (?,?, ?, ?, ?, ?, ?,?)',
    [id, name, image, description, req.user.id, templates, categoryId, created_at],
    (err, results) => {
      if (err) {
        console.error('Erreur lors de la création du lib: ' + err.stack);
        res.status(500).send('Erreur lors de la création de lib.');
        return;
      }
      res.status(201).json({ id, name, description, user_id: req.user.id, templates, categoryId, created_at });
    }
  );
});
app.put('/library/:id', authenticateUser, (req, res) => {
  const { id } = req.params;
  const { name, description, templates } = req.body;
  if (!req.user.id) {
    return res.status(401).json({
      message: "Vous devez être connecté pour effectuer cette action.",
    });
  }
  connection.execute(
    "UPDATE libraries SET name = ?, description= ?, templates=? WHERE library_id = ?",
    [name, description, templates, id],
    (err, results) => {
      if (err) {
        console.error('Erreur lors de la MAJ du lib: ' + err.stack);
        res.status(500).send('Erreur lors de la MAJ de lib.');
        return;
      }
      res.status(201).json({ id, name, description, user_id: req.user.id, templates });
    }
  );
});
server.listen(8100, () => {
  console.log("Le serveur écoute sur le port 8100");
});
module.exports = { app, connection };
