const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');
const mysql = require('mysql');
const bcrypt = require('bcrypt-nodejs');
const jwt = require('jsonwebtoken');
const config = require(__dirname + '/config.js');
const nodemailer = require('nodemailer');

// Use body parser to parse JSON body
router.use(bodyParser.json());
const connAttrs = mysql.createConnection(config.connection);

router.get('/', function (req, res) {
    res.sendfile('/')
});

/*  **************************************************************************************
************************************** User login (Both admin, ict and normal user)
*************************************
*/
router.post('/signin', function (req, res) {

    let user1 = {
        email: req.body.email,
        password: req.body.password
    }
    if (!user1) {
        return res.status(400).send({
            error: true,
            message: 'Please provide login details'
        });
    }
    connAttrs.query("SELECT * FROM users where email=? AND deleted_yn ='N'", user1.email, function (error, result) {
        if (error || result < 1) {
            res.set('Content-Type', 'application/json');
            var status = error ? 500 : 404;
            res.status(status).send(JSON.stringify({
                status: status,
                message: error ? "Error getting the that email" : "Email you have entered is Incorrect. Kindly Try Again. or Contact systemadmin",
                detailed_message: error ? error.message : ""
            }));
            console.log('========= You have Got an error ================ for this User: ' + user1.email);
            return (error);
        } else {
            user = result[0];


            bcrypt.compare(req.body.password, user.password, function (error, pwMatch) {
                var payload;
                if (error) {
                    return (error);
                }
                if (!pwMatch) {
                    res.status(401).send({
                        message: 'Wrong Password. please Try Again .'
                    });
                    return;
                }
                payload = {
                    sub: user.email,
                    entity_id: user.user_id,
                    username: user.username,
                    role: user.role
                };

                res.status(200).json({
                    user: {
                        username: user.username,
                        role: user.role
                    },
                    token: jwt.sign(payload, config.jwtSecretKey, {
                        expiresIn: 60 * 60 * 24
                    }) //EXPIRES IN ONE DAY,
                });
                res.end();
            });
        }

    });

});

/*  **************************************************************************************
************************************** User Register 
*************************************
*/
// register a new user
router.post('/register', function post(req, res, next) { // 

    // var token = req.body.token;
    // if (!token) return res.status(401).send({
    //     auth: false,
    //     message: 'No token provided.'
    // });

    // jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
    //     if (err) {
    //         return res.status(500).send({
    //             auth: false,
    //             message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
    //         });
    //     }

    var user = {
        // created_by: decoded.username,
        created_by: req.body.created_by,
        username: req.body.username,
        email: req.body.email,
        role: req.body.role,
        department_id: req.body.department_id,
        section_id: req.body.section_id,
        station_id: req.body.station_id,
        first_name: req.body.first_name,
        last_name: req.body.last_name,
        age: req.body.age,
        employment_year: req.body.employment_year

    };
    var unhashedPassword = req.body.password;
    bcrypt.genSalt(10, function (err, salt) {
        if (err) {
            return next(err);
        }
        // console.log(password);
        bcrypt.hash(unhashedPassword, salt, null, function (err, hash) {
            if (err) {
                return next(err);
            }
            // console.log(hash);
            user.hashedPassword = hash;

            connAttrs.query(

                'SELECT * FROM users where email=?', user.email, function (error, result) {
                    if (error || result.length > 0) {
                        res.set('Content-Type', 'application/json');
                        var status = error ? 500 : 404;
                        res.status(status).send(JSON.stringify({
                            status: status,
                            message: error ? "Error getting the server" : "Email you have entered is already taken.",
                            detailed_message: error ? error.message : `If user with this ${user.email} is nolonger with you please remove his details from the system`
                        }));
                        console.log("error occored");
                        return (error);
                    }
                    connAttrs.query("INSERT INTO users SET ? ", {
                        role: user.role,
                        email: user.email,
                        username: user.username,
                        password: user.hashedPassword,
                        created_by: user.created_by,
                        department_id: user.department_id,
                        section_id: user.section_id,
                        station_id: user.station_id,
                        first_name: user.first_name,
                        last_name: user.last_name,
                        age: user.age,
                        employment_year: user.employment_year

                    }, function (error, results) {
                        if (error) {
                            res.set('Content-Type', 'application/json');
                            res.status(500).send(JSON.stringify({
                                status: 500,
                                message: "Error Posting your details",
                                detailed_message: error.message
                            }));
                        } else {
                            console.log(`${user.role}: ${user.username}, succesfully added by: ${user.created_by} on ${new Date()}`);
                            return res.contentType('application/json').status(201).send(JSON.stringify(results));
                        }
                    })
                })
        })
    })
    // })
});

/*  **************************************************************************************
************************************** Adding new CAtegory
*************************************
*/
router.post('/newCategory', function (req, res) {
    var category = {
        category_name: req.body.category_name,
        details: req.body.details
    }
    // token
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        connAttrs.query(

            "SELECT * FROM category where category_name=? and deleted_yn='N'", category.category_name, function (error, result) {
                if (error || result.length > 0) {
                    res.set('Content-Type', 'application/json');
                    var status = error ? 500 : 404;
                    res.status(status).send(JSON.stringify({
                        status: status,
                        message: error ? "Error getting the server" : `Category you have entered was already captured on ${result[0].created_date}`,
                        detailed_message: error ? error.message : `If category ${category.name} is nolonger in use please remove it from the system`
                    }));
                    console.log("error occured");
                    return (error);
                }
                connAttrs.query("INSERT INTO category SET ? ", {
                    category_name: category.category_name,
                    details: category.details,
                    created_by: decoded.entity_id
                }, function (error, results) {
                    if (error) {
                        res.set('Content-Type', 'application/json');
                        res.status(500).send(JSON.stringify({
                            status: 500,
                            message: "Error Posting new Category",
                            detailed_message: error.message
                        }));
                    } else {
                        console.log(`${decoded.role}: ${decoded.username}, succesfully added category: ${category.name} on ${new Date()}`);
                        return res.contentType('application/json').status(201).send(JSON.stringify(results));
                    }
                })
            })

    });
});

/*  **************************************************************************************
************************************** Adding new Equipement
*************************************
*/
router.post('/newEquipement', function (req, res) {
    var items = {
        equipement_name: req.body.equipement_name,
        category_id: req.body.category_id,
        details: req.body.details,
        equipement_type: req.body.equipement_type,
        equipement_brand: req.body.equipement_brand,
        equipement_serial: req.body.equipement_serial
    }
    // token
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        connAttrs.query("INSERT INTO equipement SET ? ", {
            equipement_name: items.equipement_name,
            details: items.details,
            created_by: decoded.entity_id,
            category_id: items.category_id,
            equipement_type: items.equipement_type,
            equipement_brand: items.equipement_brand,
            equipement_serial: items.equipement_serial
        }, function (error, results) {
            if (error) {
                res.set('Content-Type', 'application/json');
                res.status(500).send(JSON.stringify({
                    status: 500,
                    message: "Error Posting new Item",
                    detailed_message: error.message
                }));
            } else {
                console.log(`${decoded.role}: ${decoded.username}, succesfully added Equipement: ${items.name} on ${new Date()}`);
                return res.contentType('application/json').status(201).send(JSON.stringify(results));
            }
        })


    });
});


/*  **************************************************************************************
************************************** Pullling existing categories
*************************************
*/
router.post('/categories', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT category_id, category_name, details FROM category WHERE deleted_yn='N'";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Categories found",
                    detailed_message: error ? error.message : "Sorry there are no categories set. Please set categories first"
                }));
                console.log(error);
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`categories selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

/*  **************************************************************************************
************************************** Pulling all equipements
*************************************
*/
router.post('/equipements', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM vw_equipement order by equipement_id desc";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Equipements found",
                    detailed_message: error ? error.message : "Sorry there are no Equipements set. Please consider setting up new Equipements"
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Equipements selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});


/*  **************************************************************************************
************************************** Pulling all Allocated equipements
*************************************
*/
router.post('/allocatedEquipements', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM vw_equipement_allocated order by equipement_id desc"; 
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Equipements found",
                    detailed_message: error ? error.message : "Sorry there are no Equipements set. Please consider setting up new Equipements"
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Equipements selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

/*  **************************************************************************************
************************************** Pulling all equipements Damaged
*************************************
*/
router.post('/damagedEquipements', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM vw_equipement where allocated_yn='N' and to_repair_yn='N' and damaged_yn='Y' order by equipement_id desc";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Equipements found",
                    detailed_message: error ? error.message : "Sorry there are no Equipements set. Please consider setting up new Equipements"
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Equipements selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

/*  **************************************************************************************
************************************** Pulling all equipements instore
*************************************
*/
router.post('/storeEquipements', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM vw_equipement where allocated_yn='N' and to_repair_yn='N' and damaged_yn='N' order by equipement_id desc";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Equipements found",
                    detailed_message: error ? error.message : "Sorry there are no Equipements set. Please consider setting up new Equipements"
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Equipements selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

/*  **************************************************************************************
************************************** Pulling all equipements under repaire
*************************************
*/
router.post('/repaireEquipements', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM vw_equipement where to_repair_yn='Y' and allocated_yn='N' and damaged_yn='N' order by equipement_id desc";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Equipements found",
                    detailed_message: error ? error.message : "Sorry there are no Equipements set. Please consider setting up new Equipements"
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Equipements selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

router.post('/updateCategory', function (req, res) {
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        } else {
            console.log('sub', decoded.sub)
            let itemToUpdate = {
                category_name: req.body.category_name,
                category_id: req.body.category_id,
                details: req.body.details,
                updated_by: decoded.username,
                updated_at: new Date()

            }

            if (!itemToUpdate) {
                return res.status(400).send({
                    error: true,
                    message: 'Please provide details to send'
                });
            }
            let sql = "UPDATE category SET details=?, category_name=?, updated_date = ?, updated_by=? WHERE category_id=?"
            connAttrs.query(sql, [itemToUpdate.description, itemToUpdate.category_name,
            itemToUpdate.updated_at, itemToUpdate.updated_by, itemToUpdate.category_id],
                function (error, results) {
                    if (error) {
                        res.set('Content-Type', 'application/json');
                        res.status(500).send(JSON.stringify({
                            status: 500,
                            message: "Error Updating category",
                            detailed_message: error.message
                        }));
                    } else {
                        return res.contentType('application/json').status(201).send(JSON.stringify(results));
                    }
                })

            console.log("=========================================Post:/update Released=========================")

        }
    })
})


// delete category
router.post('/deleteCategory', function (req, res) {
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        } else {
            let categoryTodelete = {
                category_id: req.body.category_id,
                deleted_by: decoded.username

            }

            if (!categoryTodelete) {
                return res.status(400).send({
                    error: true,
                    message: 'Please provide details to send'
                });
            }
            let sql = "UPDATE category SET deleted_yn='Y', deleted_by=? WHERE category_id=?"
            connAttrs.query(sql, [categoryTodelete.deleted_by, categoryTodelete.id],
                function (error, results) {
                    if (error) {
                        res.set('Content-Type', 'application/json');
                        res.status(500).send(JSON.stringify({
                            status: 500,
                            message: "Error Deleting your details",
                            detailed_message: error.message
                        }));
                    } else {
                        return res.contentType('application/json').status(201).send(JSON.stringify(results));
                    }
                })

            console.log("=========================================Post:/CategoryDelete Released=========================")

        }
    })
})

// delete Item
router.post('/deleteItem', function (req, res) {
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        } else {
            let itemTodelete = {
                equipement_id: req.body.equipement_id,
                deleted_by: decoded.username

            }

            if (!itemTodelete) {
                return res.status(400).send({
                    error: true,
                    message: 'Please provide details to send'
                });
            }
            let sql = "UPDATE equipement SET deleted_yn='Y', deleted_by=? WHERE equipement_id=?"
            connAttrs.query(sql, [itemTodelete.deleted_by, itemTodelete.equipement_id],
                function (error, results) {
                    if (error) {
                        res.set('Content-Type', 'application/json');
                        res.status(500).send(JSON.stringify({
                            status: 500,
                            message: "Error Deleteing your details",
                            detailed_message: error.message
                        }));
                    } else {
                        return res.contentType('application/json').status(201).send(JSON.stringify(results));
                    }
                })

            console.log("=========================================Post:/ItemDelete Released=========================")

        }
    })
})

// delete User
router.post('/deleteUser', function (req, res) {
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        } else {
            let userTodelete = {
                user_id: req.body.id,
                deleted_by: decoded.username

            }

            if (!userTodelete) {
                return res.status(400).send({
                    error: true,
                    message: 'Please provide details to send'
                });
            }
            let sql = "UPDATE users SET deleted_yn='Y', deleted_by=? WHERE user_id=?"
            connAttrs.query(sql, [userTodelete.deleted_by, userTodelete.user_id],
                function (error, results) {
                    if (error) {
                        res.set('Content-Type', 'application/json');
                        res.status(500).send(JSON.stringify({
                            status: 500,
                            message: "Error Deleteing your details",
                            detailed_message: error.message
                        }));
                    } else {
                        return res.contentType('application/json').status(201).send(JSON.stringify(results));
                    }
                })

            console.log("=========================================Post:/UserDelete Released=========================")

        }
    })
})


// new department
router.post('/newDepartment', function (req, res) {
    var department = {
        department_name: req.body.department_name,
        details: req.body.details,
        department_incharge: req.body.department_incharge
    }
    // token
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        connAttrs.query(

            "SELECT * FROM department where department_name= ? and deleted_yn='N'", department.department_name, function (error, result) {
                if (error || result.length > 0) {
                    res.set('Content-Type', 'application/json');
                    var status = error ? 500 : 404;
                    res.status(status).send(JSON.stringify({
                        status: status,
                        message: error ? "Error getting the server" : `Department you have entered was already captured on ${result[0].created_date}`,
                        detailed_message: error ? error.message : `If department ${department.department_name} is nolonger in use please remove it from the system`
                    }));
                    console.log("error occured");
                    return (error);
                }
                connAttrs.query("INSERT INTO department SET ? ", {
                    department_name: department.department_name,
                    details: department.details,
                    created_by: decoded.entity_id,
                    department_incharge: department.department_incharge
                }, function (error, results) {
                    if (error) {
                        res.set('Content-Type', 'application/json');
                        res.status(500).send(JSON.stringify({
                            status: 500,
                            message: "Error Posting new Department",
                            detailed_message: error.message
                        }));
                    } else {
                        console.log(`${decoded.role}: ${decoded.username}, succesfully added Department: ${department.department_name} on ${new Date()}`);
                        return res.contentType('application/json').status(201).send(JSON.stringify(results));
                    }
                })
            })

    });
});

// sections

// new section
router.post('/newSection', function (req, res) {
    var section = {
        department_id: req.body.department_id,
        section_name: req.body.section_name,
        details: req.body.details,
        section_incharge: req.body.section_incharge
    }
    // token
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        connAttrs.query("INSERT INTO section SET ? ", {
            section_name: section.section_name,
            department_id: section.department_id,
            details: section.details,
            created_by: decoded.entity_id,
            section_incharge: section.section_incharge
        }, function (error, results) {
            if (error) {
                res.set('Content-Type', 'application/json');
                res.status(500).send(JSON.stringify({
                    status: 500,
                    message: "Error Posting new Ssection",
                    detailed_message: error.message
                }));
            } else {
                console.log(`${decoded.role}: ${decoded.username}, succesfully added Section: ${section.section_name} on ${new Date()}`);
                return res.contentType('application/json').status(201).send(JSON.stringify(results));
            }
        })

    });
});


// station
router.post('/newStation', function (req, res) {
    var station = {
        station_name: req.body.station_name,
        details: req.body.details,
        station_incharge: req.body.station_incharge
    }
    // token
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        connAttrs.query(

            "SELECT * FROM station where station_name=? and deleted_yn='N'", station.station_name, function (error, result) {
                if (error || result.length > 0) {
                    res.set('Content-Type', 'application/json');
                    var status = error ? 500 : 404;
                    res.status(status).send(JSON.stringify({
                        status: status,
                        message: error ? "Error getting the server" : `Sation you have entered was already captured on ${result[0].created_date}`,
                        detailed_message: error ? error.message : `If station ${sataion.station_name} is nolonger in use please remove it from the system`
                    }));
                    console.log("error occured");
                    return (error);
                }
                connAttrs.query("INSERT INTO station SET ? ", {
                    station_name: station.station_name,
                    details: station.details,
                    created_by: decoded.entity_id,
                    station_incharge: station.station_incharge
                }, function (error, results) {
                    if (error) {
                        res.set('Content-Type', 'application/json');
                        res.status(500).send(JSON.stringify({
                            status: 500,
                            message: "Error Posting new Sataion",
                            detailed_message: error.message
                        }));
                    } else {
                        console.log(`${decoded.role}: ${decoded.username}, succesfully added Station: ${station.station_name} on ${new Date()}`);
                        return res.contentType('application/json').status(201).send(JSON.stringify(results));
                    }
                })
            })

    });
});


/*  **************************************************************************************
************************************** Pulling all stations or deports
*************************************
*/
router.post('/stations', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM station where deleted_yn='N'";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Station found",
                    detailed_message: error ? error.message : "Sorry there are no Station set. Please consider setting up new stations"
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Stations selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});


/*  **************************************************************************************
************************************** Pulling all departments
*************************************
*/
router.post('/departments', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM department where deleted_yn='N'";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Department found",
                    detailed_message: error ? error.message : "Sorry there are no Departments set. Please consider setting up new Department"
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Department selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});


/*  **************************************************************************************
************************************** Pulling all sections
*************************************
*/
router.post('/sections', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM vw_sections order by section_id desc";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Sections found",
                    detailed_message: error ? error.message : "Sorry there are no Sections set. Please consider setting up new Sections"
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Sections selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});


/*  **************************************************************************************
************************************** Pulling all users
*************************************
*/
router.post('/users', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM vw_user_details order by user_id desc";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Users found",
                    detailed_message: error ? error.message : "Sorry there are no Users set. Please consider setting up new User"
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Users selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// Assign equipement

router.post('/allocate', function (req, res) {
    var dataToAssign = {
        category_id: req.body.category_id,
        equipement_id: req.body.equipement_id,
        allocate_to: req.body.allocate_to
    }
    // token
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        connAttrs.query("INSERT INTO equipment_transaction SET ? ", {
            log_type: 'Allocated',
            category_id: dataToAssign.category_id,
            equipement_id: dataToAssign.equipement_id,
            allocate_to: dataToAssign.allocate_to,
            allocated_by: decoded.entity_id,
            allocated_date: new Date()
        }, function (error, results) {
            if (error) {
                res.set('Content-Type', 'application/json');
                res.status(500).send(JSON.stringify({
                    status: 500,
                    message: "Error Assinging that Equipement",
                    detailed_message: error.message
                }));
            } else {
                console.log(`${decoded.role}: ${decoded.username}, succesfully Allocated: ${dataToAssign.equipement_id} on ${new Date()}`);
                return res.contentType('application/json').status(201).send(JSON.stringify(results));
            }
        })

    });
});


// to repaire
// equipement

router.post('/toRepair', function (req, res) {
    var dataToRepair = {
        category_id: req.body.category_id,
        equipement_id: req.body.equipement_id,
        company_repair: req.body.company_repair

    }
    // token
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        connAttrs.query("INSERT INTO equipment_transaction SET ? ", {
            log_type: 'To repair',
            category_id: dataToRepair.category_id,
            equipement_id: dataToRepair.equipement_id,
            company_repair: dataToRepair.company_repair,
            to_repair_by: decoded.entity_id,
            date_to_repair: new Date()
        }, function (error, results) {
            if (error) {
                res.set('Content-Type', 'application/json');
                res.status(500).send(JSON.stringify({
                    status: 500,
                    message: "Error Sending that Equipement for repair",
                    detailed_message: error.message
                }));
            } else {
                console.log(`${decoded.role}: ${decoded.username}, succesfully Sent to Repair: ${dataToRepair.equipement_id} on ${new Date()}`);
                return res.contentType('application/json').status(201).send(JSON.stringify(results));
            }
        })

    });
});

// Damaged
// equipement

router.post('/damaged', function (req, res) {
    var dataToDamage = {
        category_id: req.body.category_id,
        equipement_id: req.body.equipement_id

    }
    // token
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        connAttrs.query("INSERT INTO equipment_transaction SET ? ", {
            log_type: 'Damaged',
            category_id: dataToDamage.category_id,
            equipement_id: dataToDamage.equipement_id,
            damaged_rendared_by: decoded.entity_id,
            damaged_date: new Date()
        }, function (error, results) {
            if (error) {
                res.set('Content-Type', 'application/json');
                res.status(500).send(JSON.stringify({
                    status: 500,
                    message: "Error Sending that Equipement to Damaged Repository",
                    detailed_message: error.message
                }));
            } else {
                console.log(`${decoded.role}: ${decoded.username}, succesfully Sent to Damaged: ${dataToDamage.equipement_id} on ${new Date()}`);
                return res.contentType('application/json').status(201).send(JSON.stringify(results));
            }
        })

    });
});


// To Store
// equipement

router.post('/toStore', function (req, res) {
    var dataToStore = {
        category_id: req.body.category_id,
        equipement_id: req.body.equipement_id

    }
    // token
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        connAttrs.query("INSERT INTO equipment_transaction SET ? ", {
            log_type: 'Store',
            category_id: dataToStore.category_id,
            equipement_id: dataToStore.equipement_id            
        }, function (error, results) {
            if (error) {
                res.set('Content-Type', 'application/json');
                res.status(500).send(JSON.stringify({
                    status: 500,
                    message: "Error Sending that Equipement to Store",
                    detailed_message: error.message
                }));
            } else {
                console.log(`${decoded.role}: ${decoded.username}, succesfully Sent to Store: ${dataToStore.equipement_id} on ${new Date()}`);
                return res.contentType('application/json').status(201).send(JSON.stringify(results));
            }
        })

    });
});

/*  **************************************************************************************
************************************** Pulling all open request for allocation
*************************************
*/
router.post('/openRequests', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM vw_request_open";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No OpenRequest found",
                    detailed_message: error ? error.message : "Sorry there are no open request."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All open request selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

/*  **************************************************************************************
************************************** Pulling all closed request for allocation
*************************************
*/
router.post('/closedRequests', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM vw_request_closed";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No ClosedRequest found",
                    detailed_message: error ? error.message : "Sorry there are no Closed request."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Closed request selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

/*  **************************************************************************************
************************************** Total Users
*************************************
*/
router.post('/totalUsers', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "select count(*) total_users FROM users WHERE deleted_yn = 'N'";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Active users found",
                    detailed_message: error ? error.message : "Sorry there are no Active Users."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All TottalActive users request selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

/*  **************************************************************************************
************************************** Total active Equipements
*************************************
*/
router.post('/activeEquipements', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "select count(*) total_equipements from equipement where deleted_yn = 'N';";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Active equipements found",
                    detailed_message: error ? error.message : "Sorry there are no Active Equipements."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All totalActive request selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

/*  **************************************************************************************
************************************** total equipemnts damaged
*************************************
*/
router.post('/totalDamaged', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "select count(*) total_equipements_damage from equipement where deleted_yn = 'N' and status = 'Damaged'";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Damaged Equipements found",
                    detailed_message: error ? error.message : "Sorry there are no damaged equipements."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All total Damaged Equipements selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

/*  **************************************************************************************
************************************** total equipements under repair
*************************************
*/
router.post('/totalRepair', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "select count(*) total_equipements_repair from equipement where deleted_yn = 'N' and status = 'To repair'";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Equipements under repair found",
                    detailed_message: error ? error.message : "Sorry there are no equipements under repair."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All total Equipements under repair selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

/*  **************************************************************************************
************************************** total Equipements in store
*************************************
*/
router.post('/totalInStore', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "select count(*) total_equipements_store from equipement where deleted_yn = 'N' and status = 'Store';";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Equipements in store found",
                    detailed_message: error ? error.message : "Sorry there are no Equipements in store."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Total equipements in store selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

/***
 * requesting for equipement
 *  */ 
router.post('/newRequest', function (req, res) {
    var newRequest = {
        category_id: req.body.category_id,
        details: req.body.details

    }
    // token
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        connAttrs.query("INSERT INTO equip_request SET ? ", {            
            category_id: newRequest.category_id,
            details: newRequest.details,
            user_id: decoded.entity_id            
        }, function (error, results) {
            if (error) {
                res.set('Content-Type', 'application/json');
                res.status(500).send(JSON.stringify({
                    status: 500,
                    message: "Error Sending that request",
                    detailed_message: error.message
                }));
            } else {
                console.log(`${decoded.role}: ${decoded.username}, succesfully Sent request: ${newRequest.category_id} on ${new Date()}`);
                return res.contentType('application/json').status(201).send(JSON.stringify(results));
            }
        })

    });
});
/*  **************************************************************************************
************************************** Pulling station report based on  allocation
*************************************
*/
router.post('/stationReport', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM vw_station_allocated_eqp";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No report found",
                    detailed_message: error ? error.message : "Sorry there are no reports."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Stationreport request selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

/*  **************************************************************************************
************************************** Pulling category report
*************************************
*/
router.post('/categoryReport', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM vw_category_equip";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No report found",
                    detailed_message: error ? error.message : "Sorry there are no reports."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All category request selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

/*******
 * LOgs
 */

router.post('/logsEquipementAllocated', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM vw_equipement_allocation_track";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No record found",
                    detailed_message: error ? error.message : "Sorry there are no record."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All allocatedEquipements logs request selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// damaged
router.post('/logsEquipementDamaged', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM vw_equipement_damaged_track";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No record found",
                    detailed_message: error ? error.message : "Sorry there are no record."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All allocatedEquipements logs request selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// repaire
router.post('/logsEquipementRepair', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM vw_equipement_repair_track";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No record found",
                    detailed_message: error ? error.message : "Sorry there are no record."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All allocatedEquipements logs request selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});
module.exports = router;
