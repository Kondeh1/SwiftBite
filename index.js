import express from "express";
import axios from "axios";
import pg from "pg";
import bodyParser from "body-parser";
import env from "dotenv";
import bcrypt, { hash } from "bcrypt";
import passport from "passport";
import GoogleStrategy from "passport-google-oauth2";
import { Strategy } from "passport-local";
import session from "express-session";
import flash from "connect-flash";
import { Server } from "socket.io";
import http from "http";
import crypto from "crypto";
import nodemailer from "nodemailer";
import multer from "multer";
import path from "path";
import { v4 as uuidv4 } from "uuid";

env.config();

const app = express();
const port = process.env.PORT || 3000;
const saltRound = 10;
const server = http.createServer(app);
const io = new Server(server);

io.on("connection", (socket) => {
  socket.on("joinRestaurantRoom", (resId) => {
    const roomName = `restaurant_${resId}`;
    socket.join(roomName);
    console.log(`Staff connected to: ${roomName}`);
  });
});

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    type: "OAuth2",
    user: process.env.EMAIL_USER,
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    refreshToken: process.env.GOOGLE_REFRESH_TOKEN,
  },
  tls: {
    rejectUnauthorized: false,
  },
});

const storage = multer.diskStorage({
  destination: "./public/uploads/menu/",
  filename: (req, file, cb) => {
    cb(null, "food-" + Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({ storage: storage });

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
  }),
);

app.use(flash());

app.use(passport.session());
app.use(passport.initialize());
app.use(express.json());

app.use((req, res, next) => {
  const message = req.flash("error");
  res.locals.error = message;
  next();
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

const db = new pg.Client({
  user: "postgres",
  host: process.env.HOST_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  database: "SwiftBite",
});

db.connect();

app.get("/", async (req, res) => {
  res.render("landing.ejs");
});

app.get("/getstarted", (req, res) => {
  res.render("index.ejs");
});

app.get("/singup", (req, res) => {
  res.render("singup.ejs");
});

app.get("/login", (req, res) => {
  res.render("index.ejs");
});

app.get("/forget", async (req, res) => {
  res.render("forgetPassword.ejs");
});

app.use((req, res, next) => {
  // If the cart exists, sum up the quantities; otherwise, it's 0
  if (req.session.cart) {
    res.locals.cartCount = req.session.cart.reduce(
      (total, item) => total + item.quantity,
      0,
    );
  } else {
    res.locals.cartCount = 0;
  }
  next();
});

app.get("/dashboard", async (req, res) => {
  if (req.isAuthenticated()) {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [
      req.user.id,
    ]);
    const user = result.rows[0];

    if (!user.role) {
      return res.redirect("/choose-role");
    }
    const role = user.role.toLowerCase();
    // console.log(cu`role`);

    if (role === "admin") {
      res.redirect("/admin/dashboard");
    } else if (role === "staff") {
      // res.send("<h1>Welcome to Staff Dashboard");
    } else if (role === "manager") {
      res.redirect("/manager/dashboard");
    } else {
      // res.send("<h1>Welcome to customer Dashboard");
      res.redirect("/customer/home");
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/test-order", (req, res) => {
  const restaurantId = 46; // Your specific ID
  const roomName = `restaurant_${restaurantId}`;

  const testData = {
    orderId: Math.floor(Math.random() * 10000),
    total: 150.0,
    restaurantId: restaurantId,
  };

  console.log(`Sending order to room: ${roomName}`);

  io.to(roomName).emit("newOrder", testData);

  res.send(`Order sent to ${roomName}. Check your dashboard!`);
});

app.get("/admin/dashboard", async (req, res) => {
  if (req.isAuthenticated() && req.user.role?.toLowerCase() === "admin") {
    try {
      const userRes = await db.query("SELECT COUNT(*) FROM users");
      const restRes = await db.query(
        "SELECT COUNT(*) FROM restaurants WHERE status = 'approved'",
      );

      const activityRes = await db.query(`
  (SELECT full_name AS actor, role, 'user_signup' AS type, created_at 
   FROM users)
  UNION ALL
  (SELECT name AS actor, 'Manager' AS role, 'restaurant_added' AS type, created_at 
   FROM restaurants)
  ORDER BY created_at DESC 
  LIMIT 5
`);

      res.render("admin/home.ejs", {
        currentPage: "dashboard",
        user: req.user,
        stats: {
          users: userRes.rows[0].count,
          restaurants: restRes.rows[0].count,
          orders: 0,
        },
        activities: activityRes.rows,
      });
    } catch (err) {
      console.error(err);
      res.status(500).send("Internal Server Error");
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/admin/verification", async (req, res) => {
  if (req.isAuthenticated() && req.user.role?.toLowerCase() === "admin") {
    try {
      const result = await db.query(
        "SELECT * FROM restaurants WHERE status = 'pending' ORDER BY created_at ASC",
      );
      console.log("Manager application: ", result);

      res.render("admin/verification.ejs", {
        currentPage: "verification",
        user: req.user,
        pendingRestaurants: result.rows,
      });
    } catch (err) {
      console.error("Database error:", err);
      res.render("admin/verification.ejs", {
        currentPage: "verification",
        user: req.user,
        pendingRestaurants: [],
        message: "Error fetching data from database.",
      });
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/admin/accounts", async (req, res) => {
  if (req.isAuthenticated() && req.user.role?.toLowerCase() === "admin") {
    try {
      const result = await db.query(
        "SELECT id, full_name, email, role, status FROM users ORDER BY created_at DESC",
      );

      res.render("admin/accounts.ejs", {
        currentPage: "accounts",
        user: req.user,
        allUsers: result.rows,
      });
    } catch (err) {
      console.error("Error fetching users:", err);
      res.status(500).send("Internal Server Error");
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/admin/monitoring", async (req, res) => {
  if (!req.isAuthenticated() || req.user.role?.toLowerCase() !== "admin") {
    return res.redirect("/login");
  }

  try {
    const revenueStats = await db.query(`
            SELECT 
                SUM(total_price) as gross_volume,
                SUM(total_price * 0.25) as admin_net,
                SUM(total_price * 0.75) as res_payout,
                COUNT(id) as total_orders
            FROM orders 
            WHERE status = 'completed'
        `);

    const weeklyData = await db.query(`
            SELECT 
                TO_CHAR(created_at, 'Dy') as day, 
                SUM(total_price * 0.25) as amount 
            FROM orders 
            WHERE created_at > NOW() - INTERVAL '7 days' AND status = 'completed'
            GROUP BY day, TO_CHAR(created_at, 'ID')
            ORDER BY TO_CHAR(created_at, 'ID')
        `);

    const monthlyData = await db.query(`
            SELECT 
                TO_CHAR(created_at, 'Mon') as month, 
                SUM(total_price * 0.25) as amount 
            FROM orders 
            WHERE created_at > DATE_TRUNC('year', NOW()) AND status = 'completed'
            GROUP BY month, EXTRACT(MONTH FROM created_at)
            ORDER BY EXTRACT(MONTH FROM created_at)
        `);

    res.render("admin/monitoring.ejs", {
      user: req.user,
      currentPage: "monitoring",
      totalRevenue: revenueStats.rows[0].gross_volume || 0,
      stats: revenueStats.rows[0],
      weeklyData: weeklyData.rows,
      monthlyData: monthlyData.rows,
    });
  } catch (err) {
    console.error("Monitoring Error:", err);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/admin/settings", async (req, res) => {
  if (req.isAuthenticated() && req.user.role?.toLowerCase() === "admin") {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [
      req.user.id,
    ]);
    res.render("admin/settings.ejs", {
      currentPage: "settings",
      user: result.rows[0],
    });
  } else {
    res.redirect("/login");
  }
});

app.get("/manager/dashboard", (req, res) => {
  res.render("manager/home.ejs", { user: req.user, currentPage: "dashboard" });
});

app.get("/manager/menuManagement", async (req, res) => {
  if (!req.user) return res.redirect("/login");

  try {
    const resResult = await db.query(
      "SELECT * FROM restaurants WHERE owner_id = $1",
      [req.user.id],
    );

    const restaurant = resResult.rows[0];
    let menuItems = [];

    if (restaurant && restaurant.status === "approved") {
      const menuResult = await db.query(
        "SELECT * FROM menus WHERE restaurant_id = $1 ORDER BY created_at DESC",
        [restaurant.id],
      );
      menuItems = menuResult.rows;
    }

    res.render("manager/menuManagement.ejs", {
      restaurant: restaurant || { status: "none" },
      menuItems: menuItems,
      currentPage: "menuManagement",
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Database Error");
  }
});

// app.get("/staff/dashboard", async (req, res) => {
//   try {
//     const staffResult = await db.query(
//       "SELECT restaurant_id FROM staff WHERE id = $1",
//       [req.user.id],
//     );

//     if (staffResult.rows.length === 0) {
//       return res.status(404).send("Staff restaurant not found");
//     }

//     const restaurantId = staffResult.rows[0].restaurant_id;

//     const activeOrders = await db.query(
//       "SELECT COUNT(*) FROM orders WHERE restaurant_id = $1 AND status != 'completed'",
//       [restaurantId],
//     );

//     const totalToday = await db.query(
//       "SELECT COUNT(*) FROM orders WHERE restaurant_id = $1 AND created_at::date = CURRENT_DATE",
//       [restaurantId],
//     );

//     const restaurantName = await db.query(
//       "SELECT name FROM restaurants WHERE id = $1",
//       [restaurantId],
//     );

//     res.render("staff/home.ejs", {
//       restaurantId: restaurantId,
//       activeOrdersCount: activeOrders.rows[0].count,
//       totalOrdersToday: totalToday.rows[0].count,
//       restaurantName: restaurantName.rows[0]?.name,
//       currentPage: "dashboard",
//     });
//   } catch (err) {
//     console.error(err);
//     res.status(500).send("Server Error");
//   }
// });

app.get("/staff/dashboard", async (req, res) => {
  try {
    const staffId = req.user?.id;
    if (!staffId) return res.redirect("/login");

    // 1. Get restaurant_id (staff.id is UUID, staff.restaurant_id is Integer)
    const staffData = await db.query(
      "SELECT restaurant_id FROM staff WHERE id = $1::uuid",
      [staffId],
    );

    if (staffData.rows.length === 0) {
      console.error("No staff found for ID:", staffId);
      return res.status(404).send("Staff profile not found.");
    }

    const restaurantId = staffData.rows[0].restaurant_id;

    // 2. Fetch all data in parallel using the Integer restaurantId
    const [activeOrders, restaurantName, completedToday, recentOrders] =
      await Promise.all([
        db.query(
          "SELECT COUNT(*) FROM orders WHERE restaurant_id = $1 AND status != 'completed'",
          [restaurantId],
        ),
        db.query("SELECT name FROM restaurants WHERE id = $1", [restaurantId]),
        db.query(
          `SELECT COUNT(*) FROM orders 
         WHERE restaurant_id = $1 
         AND status = 'completed' 
         AND created_at::date = CURRENT_DATE`,
          [restaurantId],
        ),
        db.query(
          `SELECT id as order_id, total_price as amount, status as type, created_at 
         FROM orders 
         WHERE restaurant_id = $1 
         ORDER BY created_at DESC LIMIT 5`,
          [restaurantId],
        ),
      ]);

    // 3. Format activities for EJS
    const activities = recentOrders.rows.map((order) => ({
      ...order,
      type: order.type === "pending" ? "new_order" : order.type,
    }));

    // 4. Final Render
    res.render("staff/home.ejs", {
      restaurantId: restaurantId,
      restaurantName: restaurantName.rows[0]?.name || "SwiftBite Partner",
      activeOrdersCount: activeOrders.rows[0].count || 0,
      totalOrdersToday: completedToday.rows[0].count || 0,
      activities: activities,
      currentPage: "dashboard",
    });
  } catch (err) {
    console.error("Dashboard Error:", err);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/staff/new-orders", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");

  try {
    const staffId = req.user.id;
    console.log("Logged in Staff UUID:", staffId); // DEBUG

    const staffData = await db.query(
      "SELECT restaurant_id FROM staff WHERE id = $1::uuid",
      [staffId],
    );

    if (staffData.rows.length === 0) {
      console.log("No staff member found for this ID!"); // DEBUG
      return res.render("staff/incoming.ejs", {
        orders: [],
        pendingCount: 0,
        currentPage: "new-orders",
      });
    }

    const restaurantId = staffData.rows[0].restaurant_id;
    console.log("Fetching orders for Restaurant ID:", restaurantId); // DEBUG

    // Inside app.get("/staff/new-orders")
    const incomingOrders = await db.query(
      `SELECT 
    o.id as order_id, 
    o.total_price as amount, 
    o.status, 
    o.created_at, 
    u.full_name as customer_name
   FROM orders o
   JOIN users u ON o.customer_id = u.id 
   WHERE o.restaurant_id = $1 
   AND o.status IN ('pending', 'pending_payment', 'confirmed') 
   ORDER BY o.created_at ASC`,
      [restaurantId],
    );

    console.log("Orders found in DB:", incomingOrders.rows.length); // DEBUG

    res.render("staff/incoming.ejs", {
      orders: incomingOrders.rows,
      restaurantId: restaurantId,
      pendingCount: incomingOrders.rows.length,
      currentPage: "new-orders",
    });
  } catch (err) {
    console.error("Error loading new orders:", err);
    res.status(500).send("Error loading orders page.");
  }
});

app.get("/staff/tracking", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");

  try {
    const staffId = req.user.id;

    // 1. Get the restaurant_id for this staff member
    const staffData = await db.query(
      "SELECT restaurant_id FROM staff WHERE id = $1::uuid",
      [staffId],
    );

    if (staffData.rows.length === 0) {
      return res.status(404).send("Staff profile not found.");
    }

    const restaurantId = staffData.rows[0].restaurant_id;

    // 2. Fetch tracking orders using the verified restaurantId
    const trackingOrders = await db.query(
      `SELECT id, total_price, status, items, order_type, created_at
       FROM orders 
       WHERE restaurant_id = $1 
       AND status IN ('preparing', 'delivering')
       ORDER BY created_at DESC`,
      [restaurantId],
    );

    console.log(
      `Tracking: Found ${trackingOrders.rows.length} orders for Restaurant ${restaurantId}`,
    );

    res.render("staff/tracking.ejs", {
      orders: trackingOrders.rows,
      currentPage: "tracking", // Good for sidebar highlighting
    });
  } catch (err) {
    console.error("Tracking Route Error:", err);
    res.status(500).send("Server Error");
  }
});

app.get("/staff/history", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");

  try {
    const staffId = req.user.id;
    const filterDate = req.query.date; // e.g., 2024-05-20

    // 1. Get restaurant context
    const staffData = await db.query(
      "SELECT restaurant_id FROM staff WHERE id = $1::uuid",
      [staffId],
    );
    if (staffData.rows.length === 0)
      return res.status(404).send("Staff not found.");
    const restaurantId = staffData.rows[0].restaurant_id;

    // 2. Build Query
    let queryText = `
      SELECT o.id, o.total_price, o.items, o.order_type, o.created_at, u.full_name as customer_name
      FROM orders o
      JOIN users u ON o.customer_id = u.id 
      WHERE o.restaurant_id = $1 AND o.status = 'completed'
    `;
    const queryParams = [restaurantId];

    if (filterDate) {
      queryText += ` AND o.created_at::date = $2`;
      queryParams.push(filterDate);
    }

    queryText += ` ORDER BY o.created_at DESC`;

    const historyOrders = await db.query(queryText, queryParams);

    res.render("staff/history.ejs", {
      orders: historyOrders.rows,
      currentPage: "history",
      restaurantId: restaurantId,
      selectedDate: filterDate || "",
    });
  } catch (err) {
    console.error("History Route Error:", err);
    res.status(500).send("Server Error");
  }
});

app.get("/staff/delivery", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");

  try {
    const staffId = req.user.id;

    const staffData = await db.query(
      "SELECT restaurant_id FROM staff WHERE id = $1::uuid",
      [staffId],
    );

    if (staffData.rows.length === 0)
      return res.status(404).send("Staff not found.");
    const restaurantId = staffData.rows[0].restaurant_id;

    const deliveryOrders = await db.query(
      `SELECT 
    o.id, 
    o.total_price, 
    o.status, 
    o.items, 
    o.order_type, 
    o.created_at,
    o.verification_code, -- ADD THIS LINE
    u.full_name as customer_name,
    u.phone_number as customer_phone, 
    u.address as customer_address
   FROM orders o
   JOIN users u ON o.customer_id = u.id 
   WHERE o.restaurant_id = $1 
   AND o.order_type = 'Delivery'
   AND o.status = 'delivering'
   ORDER BY o.created_at DESC`,
      [restaurantId],
    );

    res.render("staff/delivery.ejs", {
      orders: deliveryOrders.rows,
      currentPage: "delivery",
    });
  } catch (err) {
    console.error("Delivery Detail Route Error:", err);
    res.status(500).send("Server Error");
  }
});

app.post("/staff/update-order/:id", async (req, res) => {
  const orderId = req.params.id;
  const { status } = req.body; // 'preparing' or 'rejected'

  try {
    await db.query("UPDATE orders SET status = $1 WHERE id = $2", [
      status,
      orderId,
    ]);

    // Optional: Trigger a socket emit here so the customer's
    // monitoring page updates without them refreshing!

    res.json({ success: true });
  } catch (err) {
    console.error("Update Error:", err);
    res.status(500).json({ success: false });
  }
});

app.get("/customer/home", async (req, res) => {
  if (req.query.payment === "success") {
    req.flash(
      "success_msg",
      "Payment Successful! Your order is being prepared.",
    );
  }
  try {
    // We use your 'status' column and filter for 'approved'
    const result = await db.query(
      "SELECT id, name, address, image_url, status FROM restaurants WHERE status = $1",
      ["approved"],
    );

    res.render("customers/home.ejs", {
      restaurants: result.rows, // result.rows is the array for the EJS loop
      currentPage: "home",
    });
  } catch (err) {
    console.error("Error fetching approved restaurants:", err);
    res.status(500).send("Unable to load restaurants at this time.");
  }
});

app.get("/customer/restaurant/:id/menu", async (req, res) => {
  const restaurantId = req.params.id;

  try {
    // 1. Get Restaurant Details (to show the banner)
    const restaurantRes = await db.query(
      "SELECT id, name, address, image_url FROM restaurants WHERE id = $1",
      [restaurantId],
    );

    // 2. Get Menu Items (selecting only columns you have)
    // Assuming columns: id, item_name, price, image_url
    // Ensure your SQL looks like this:
    const menuRes = await db.query(
      "SELECT id, name, price, image_url, category FROM menuS WHERE restaurant_id = $1",
      [restaurantId],
    );

    if (restaurantRes.rows.length === 0) {
      return res.status(404).send("Restaurant not found");
    }

    res.render("customers/menu.ejs", {
      restaurant: restaurantRes.rows[0],
      menu: menuRes.rows,
      currentPage: "home",
    });
  } catch (err) {
    console.error("Error loading menu:", err);
    res.status(500).send("Error loading menu");
  }
});

// Make sure this is a POST route if your fetch is using POST
// Add "/customer" to the start of the path
app.post("/customer/cart/remove/:id", async (req, res) => {
  const itemId = req.params.id;

  try {
    if (req.session.cart) {
      // Logic: Keep everything EXCEPT the item we want to delete
      // We use String() to ensure we aren't comparing numbers to strings
      req.session.cart = req.session.cart.filter(
        (item) => String(item.id) !== String(itemId),
      );
    }

    res.json({
      success: true,
      message: "Item removed",
      cartCount: req.session.cart ? req.session.cart.length : 0,
    });
  } catch (error) {
    console.error("Delete Error:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/customer/cart/clear", (req, res) => {
  try {
    // Clear the cart array in the session
    req.session.cart = [];

    // Optional: Clear the total if you store it in the session
    req.session.total = 0;

    // Redirect the user back to the main restaurants page
    res.redirect("/customer/home");
  } catch (err) {
    console.error("Error clearing cart:", err);
    res.status(500).send("Could not clear cart");
  }
});

app.post("/customer/order/place", async (req, res) => {
  try {
    const cart = req.session.cart;

    // We get the total from the hidden input or calculate it here
    let total = 0;
    cart.forEach((item) => {
      total += item.price * item.quantity;
    });

    if (!cart || cart.length === 0) {
      return res.redirect("/customer/home");
    }

    // SAVE EVERYTHING TO THE SESSION
    req.session.orderSummary = {
      items: cart,
      total: total, // This is the value that was missing!
    };

    res.redirect("/customer/order/details");
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
});

// The New Details Page Route
app.get("/customer/order/details", (req, res) => {
  const order = req.session.orderSummary;
  if (!order) return res.redirect("/customer/home");

  // Calculate 50% Deposit
  const depositAmount = Number(order.total) * 0.5;

  res.render("customers/orderDetails.ejs", {
    order,
    depositAmount, // Pass this to the EJS
  });
});
app.post("/customer/order/final-confirm", async (req, res) => {
  const { address, phone, totalAmount, depositAmount, orderType } = req.body;
  const cart = req.session.cart;

  // 1. Force the customerId to be a string/UUID
  const customerId = req.user?.id || req.session?.user?.id;

  // 2. Resolve Restaurant ID as Integer
  let restaurantId =
    cart && cart.length > 0 ? parseInt(cart[0].restaurant_id) : null;
  if (!restaurantId || isNaN(restaurantId)) {
    restaurantId = parseInt(req.body.restaurantId);
  }

  // 3. STOP if customerId is missing - This prevents the Foreign Key Error
  if (!customerId) {
    console.error("ORDER BLOCKED: No valid Customer UUID found in session.");
    return res
      .status(401)
      .send("Your session has expired. Please log in again.");
  }

  try {
    const itemsString = cart
      .map((item) => `${item.quantity}x ${item.name}`)
      .join(", ");
    const finalDeposit = parseFloat(depositAmount) || 0;
    const finalTotal = parseFloat(totalAmount) || 0;

    // 4. Corrected Insert (Includes the 'deposit' column to fix Le 0.00)
    const insertQuery = `
            INSERT INTO orders (
                restaurant_id, 
                customer_id, 
                items, 
                total_price, 
                deposit, 
                status, 
                order_type, 
                created_at
            ) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) 
            RETURNING id;
        `;

    const dbResult = await db.query(insertQuery, [
      restaurantId, // $1: Integer
      customerId, // $2: UUID (The key that was failing)
      itemsString, // $3: Text
      finalTotal, // $4: Numeric
      finalDeposit, // $5: Numeric
      "pending_payment", // $6: Text
      orderType, // $7: Text
    ]);

    const orderId = dbResult.rows[0].id;

    // 5. Call Monime API
    const response = await axios.post(
      "https://api.monime.io/v1/checkout-sessions",
      {
        name: `Order #${orderId}`,
        successUrl: `http://localhost:3000/customer/payment-status?status=success&orderId=${orderId}`,
        cancelUrl: `http://localhost:3000/customer/payment-status?status=cancel&orderId=${orderId}`,
        lineItems: [
          {
            type: "custom",
            name: `Deposit for Order #${orderId}`,
            price: { currency: "SLE", value: Math.round(finalDeposit * 100) },
            quantity: 1,
          },
        ],
        metadata: { db_order_id: String(orderId) },
      },
      {
        headers: {
          "Monime-Version": "caph.2025-08-23",
          "Monime-Space-Id": "spc-k6MBGmUZjaWWDisj57tCLHDqe42",
          "Idempotency-Key": uuidv4(),
          Authorization:
            "Bearer mon_KzqK9AkqDHEk5DNXmfsPZFDPeu3rfemarNme9aLvSY3XdDrEiP3XrIQC2D2F2uCG",
          "Content-Type": "application/json",
        },
      },
    );

    if (response.data?.result?.redirectUrl) {
      res.redirect(response.data.result.redirectUrl);
    } else {
      throw new Error("Payment Gateway failed to provide redirect URL");
    }
  } catch (error) {
    console.error("CRITICAL ORDER ERROR:", error.message);
    res.status(500).send("Could not process order. Please try again.");
  }
});

app.all("/customer/payment-status", async (req, res) => {
  const { status, orderId } = req.query;

  if (status === "success") {
    req.session.cart = []; // Clear the cart in the session immediately

    try {
      // 1. Fetch the order from the database
      const result = await db.query("SELECT * FROM orders WHERE id = $1", [
        orderId,
      ]);

      if (result.rows.length === 0) {
        return res.redirect("/customer/home");
      }

      let order = result.rows[0];

      /**
       * WEBHOOK SYNC FIX:
       * If the webhook hasn't hit the DB yet, 'deposit' might still be 0.
       * We manually override these values for the view so the customer
       * doesn't see "Le 0.00" on a successful payment page.
       */
      if (order.deposit == 0 || order.status === "pending_payment") {
        order.status = "confirmed";
        // Note: We don't save this to DB here; the webhook handles the permanent save.
        // This just makes the EJS look correct right now.
      }

      // 2. Render the monitoring page
      // Ensure the path 'customers/monitoring.ejs' matches your folder structure exactly
      return res.render("customers/monitoring.ejs", {
        order: order,
        payment_success: true,
      });
    } catch (err) {
      console.error("Payment Status Error:", err);
      // Fallback: If DB fails, send them to home with the success message
      return res.redirect("/customer/home?payment=success");
    }
  } else {
    // 3. Handle Cancellation
    // Redirect back to checkout with a query param to trigger the 'Cancelled' popup
    return res.redirect("/customer/checkout?payment=cancelled");
  }
});

app.get("/customer/orders", async (req, res) => {
  const customerId = req.user?.id || req.session?.user?.id;
  if (!customerId) return res.redirect("/login");

  try {
    // Query should select ALL statuses so the user sees their active orders too
    const result = await db.query(
      `SELECT * FROM orders 
             WHERE customer_id = $1 
             ORDER BY created_at DESC`,
      [customerId],
    );

    res.render("customers/orders.ejs", { orders: result.rows });
  } catch (err) {
    console.error("History Error:", err);
    res.status(500).send("Error loading order history.");
  }
});

app.post("/webhook", async (req, res) => {
  const body = req.body;

  try {
    if (!body.event || !body.event.name) {
      return res.status(400).send("No event name found");
    }

    const eventName = body.event.name;

    if (eventName === "checkout_session.completed") {
      const session = body.data;
      const orderId = session.metadata.db_order_id;
      const amountPaid = session.metadata.deposit_paid; // Retrieve from metadata

      console.log(
        `✅ Payment Confirmed. Order #${orderId}, Deposit: Le ${amountPaid}`,
      );

      // Update Database: Set payment_status, status, and the deposit amount
      const updateQuery = `
                UPDATE orders 
                SET payment_status = 'paid', 
                    status = 'confirmed',
                    deposit = $1
                WHERE id = $2
            `;

      await db.query(updateQuery, [amountPaid, orderId]);
    }

    res.status(200).json({ received: true });
  } catch (err) {
    console.error("❌ Webhook Error:", err.message);
    res.status(400).send(`Webhook Error: ${err.message}`);
  }
});

app.get("/customer/order/monitor/:id", async (req, res) => {
  const orderId = req.params.id;
  try {
    const result = await db.query("SELECT * FROM orders WHERE id = $1", [
      orderId,
    ]);

    if (result.rows.length === 0) {
      return res.status(404).send("Order not found.");
    }

    const order = result.rows[0];

    // Ensure payment_success is explicitly passed as false
    // unless this is a fresh redirect from a successful payment
    res.render("customers/monitoring.ejs", {
      order: order,
      payment_success: req.query.payment === "success" ? true : false,
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server Error");
  }
});

app.post("/customer/order/cancel/:id", async (req, res) => {
  const orderId = req.params.id;
  const customerId = req.user
    ? req.user.id
    : req.session.user
      ? req.session.user.id
      : null;

  try {
    // 1. Fetch the order to verify ownership and status
    const orderResult = await db.query(
      "SELECT * FROM orders WHERE id = $1 AND customer_id = $2",
      [orderId, customerId],
    );

    if (orderResult.rows.length === 0) {
      return res.status(404).send("Order not found.");
    }

    const order = orderResult.rows[0];

    // 2. Prevent cancellation if the restaurant has already started (e.g., status is 'preparing' or 'delivered')
    const nonCancellableStatuses = [
      "preparing",
      "out_for_delivery",
      "delivered",
      "completed",
    ];
    if (nonCancellableStatuses.includes(order.status)) {
      return res
        .status(400)
        .send(
          "Cannot cancel. The restaurant has already started preparing your order.",
        );
    }

    // 3. Update Database to 'cancelled'
    await db.query("UPDATE orders SET status = 'cancelled' WHERE id = $1", [
      orderId,
    ]);

    // 4. REFUND LOGIC: If they paid a deposit, mark it for refund
    if (order.payment_status === "paid" && order.deposit > 0) {
      console.log(
        `Order #${orderId} cancelled. Refund of Le ${order.deposit} required.`,
      );

      // Update payment status so admin knows to process refund
      await db.query(
        "UPDATE orders SET payment_status = 'refund_pending' WHERE id = $1",
        [orderId],
      );

      // NOTE: You would typically call axios.post("monime_refund_api_url") here.
    }

    res.redirect(`/customer/order/monitor/${orderId}?status=cancelled`);
  } catch (err) {
    console.error("Cancellation Error:", err);
    res.status(500).send("Internal Server Error during cancellation.");
  }
});
// app.post("/webhook", async (req, res) => {
//   const event = req.body;
//   const orderId = event.data.metadata?.db_order_id; // Retrieve our DB ID

//   if (
//     event.event?.name === "checkout.session.completed" ||
//     event.data.status === "completed"
//   ) {
//     try {
//       // 1. Update DB to paid_deposit
//       await db.query("UPDATE orders SET status = $1 WHERE id = $2", [
//         "paid_deposit",
//         orderId,
//       ]);

//       console.log(`Order ${orderId} marked as PAID via Webhook.`);

//       // Note: You can't set req.flash here because this is a server-to-server call.
//       // The user is redirected to successUrl separately.
//       res.status(200).send("OK");
//     } catch (err) {
//       console.error("Webhook DB Error:", err);
//       res.status(500).send("DB Error");
//     }
//   } else {
//     res.status(200).send("Not completed");
//   }
// });

// Helper to simulate the API call
// async function simulatePayment(phone, amount, provider) {
//   // This is where the USSD push logic goes
//   return new Promise((resolve) => setTimeout(() => resolve(true), 3000));
// }

app.post("/customer/cart/add", (req, res) => {
  try {
    // 1. Destructure the snake_case name sent from your Menu EJS
    const { id, name, price, image, restaurant_id } = req.body;

    if (!req.session.cart) req.session.cart = [];

    const existingItemIndex = req.session.cart.findIndex(
      (item) => String(item.id) === String(id),
    );

    if (existingItemIndex !== -1) {
      req.session.cart[existingItemIndex].quantity += 1;
    } else {
      // 2. CRITICAL: Store the restaurant_id inside the session object
      req.session.cart.push({
        id,
        name,
        price: parseFloat(price),
        image,
        restaurant_id: restaurant_id,
        quantity: 1,
      });
    }

    console.log(
      "Cart Updated. Current Restaurant:",
      req.session.cart[0].restaurant_id,
    );
    res.status(200).json({ success: true, cartCount: req.session.cart.length });
  } catch (err) {
    console.error("Cart Add Error:", err);
    res.status(500).json({ success: false });
  }
});

app.get("/customer/checkout", (req, res) => {
  // Get the cart from session, or an empty array if it doesn't exist
  const cart = req.session.cart || [];

  // Calculate the Grand Total
  const total = cart.reduce((acc, item) => acc + item.price * item.quantity, 0);

  res.render("customers/checkout.ejs", {
    cart: cart,
    total: total,
    currentPage: "cart", // Keeps the sidebar link active
  });
});
app.post("/customer/verify-delivery", async (req, res) => {
  const { orderId, inputCode } = req.body;

  try {
    // 1. Fetch the stored code for this order
    const result = await db.query(
      "SELECT verification_code FROM orders WHERE id = $1",
      [orderId],
    );

    if (result.rows.length === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Order not found." });
    }

    const actualCode = result.rows[0].verification_code;

    // 2. Compare codes
    if (inputCode === actualCode) {
      // 3. Update status to 'completed' and clear the code
      await db.query(
        "UPDATE orders SET status = 'completed', verification_code = NULL WHERE id = $1",
        [orderId],
      );

      return res.json({ success: true });
    } else {
      return res.json({
        success: false,
        message: "Incorrect verification code.",
      });
    }
  } catch (err) {
    console.error("Verification Error:", err);
    res.status(500).json({ success: false, message: "Internal server error." });
  }
});

app.get(
  "/google/auth",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  }),
);

app.get(
  "/swiftbite",
  passport.authenticate("google", {
    successRedirect: "/dashboard",
    failureRedirect: "/login",
  }),
);

app.get("/choose-role", async (req, res) => {
  console.log("user new: ", req.user.full_name);
  const googleUser = req.user.full_name;
  if (req.isAuthenticated()) {
    res.render("choose-role.ejs", { name: googleUser });
  } else {
    res.redirect("/login");
  }
});

app.get("/manager/apply", (req, res) => {
  if (!req.user) return res.redirect("/login");
  res.render("manager/apply.ejs");
});

app.post(
  "/admin/update-profile-image",
  upload.single("profileImage"),
  async (req, res) => {
    if (!req.user || req.user.role.toLowerCase() !== "admin")
      return res.redirect("/login");
    try {
      if (!req.file) return res.redirect("/admin/settings");

      const imageUrl = `/uploads/menu/${req.file.filename}`;
      await db.query("UPDATE users SET profile_image = $1 WHERE id = $2", [
        imageUrl,
        req.user.id,
      ]);

      res.redirect("/admin/settings?success=img");
    } catch (err) {
      res.status(500).send("Error");
    }
  },
);

app.post(
  "/update-profile-image",
  upload.single("profileImage"),
  async (req, res) => {
    if (!req.user) return res.redirect("/login");

    try {
      if (!req.file) return res.redirect("back");

      const imageUrl = `/uploads/menu/${req.file.filename}`;

      await db.query("UPDATE users SET profile_image = $1 WHERE id = $2", [
        imageUrl,
        req.user.id,
      ]);

      const redirectPath =
        req.user.role?.toLowerCase() === "admin"
          ? "/admin/settings"
          : "/manager/settings";
      res.redirect(redirectPath);
    } catch (err) {
      console.error(err);
      res.status(500).send("Error");
    }
  },
);

app.post(
  "/manager/update-profile-image",
  upload.single("profileImage"),
  async (req, res) => {
    if (!req.user) return res.redirect("/login");

    try {
      if (!req.file) {
        const errorPath =
          req.user.role?.toLowerCase() === "admin"
            ? "/admin/settings"
            : "/manager/settings";
        return res.redirect(`${errorPath}?error=no_file`);
      }

      const imageUrl = `/uploads/menu/${req.file.filename}`;

      await db.query("UPDATE users SET profile_image = $1 WHERE id = $2", [
        imageUrl,
        req.user.id,
      ]);

      const role = req.user.role?.toLowerCase();
      if (role === "admin") {
        res.redirect("/admin/settings?success=image_updated");
      } else {
        res.redirect("/manager/settings?success=image_updated");
      }
    } catch (err) {
      console.error("Profile Image Error:", err.message);
      res.status(500).send("Error updating profile picture.");
    }
  },
);

app.post("/manager/apply", async (req, res) => {
  if (!req.user) return res.redirect("/login");

  const { restaurantName, address, contact } = req.body;

  try {
    await db.query(
      "INSERT INTO restaurants (name, address, contact_number, owner_id, status) VALUES ($1, $2, $3, $4, $5)",
      [restaurantName, address, contact, req.user.id, "pending"],
    );
    res.redirect("/manager/menuManagement");
  } catch (err) {
    console.error(err);
    res.status(500).send("Error submitting application.");
  }
});

app.post("/manager/add-menu", upload.single("foodImage"), async (req, res) => {
  if (!req.user) return res.redirect("/login");

  const { itemName, price, category } = req.body;
  const imagePath = req.file ? `/uploads/menu/${req.file.filename}` : null;

  try {
    const resResult = await db.query(
      "SELECT * FROM restaurants WHERE owner_id = $1",
      [req.user.id],
    );
    const restaurant = resResult.rows[0];

    const duplicateCheck = await db.query(
      "SELECT * FROM menus WHERE restaurant_id = $1 AND LOWER(name) = LOWER($2) AND price = $3",
      [restaurant.id, itemName.trim(), price],
    );

    if (duplicateCheck.rows.length > 0) {
      const menuResult = await db.query(
        "SELECT * FROM menus WHERE restaurant_id = $1",
        [restaurant.id],
      );

      return res.render("manager/menuManagement.ejs", {
        restaurant: restaurant,
        menuItems: menuResult.rows,
        error: "Duplicate found: This item has already been added.",
      });
    }

    await db.query(
      "INSERT INTO menus (name, price, category, image_url, restaurant_id) VALUES ($1, $2, $3, $4, $5)",
      [itemName.trim(), price, category, imagePath, restaurant.id],
    );

    res.redirect("/manager/menuManagement");
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
});
app.get("/logout", (req, res) => {
  req.logOut((err) => {
    res.render("landing.ejs");
  });
});

app.get("/resetPassword/:token", async (req, res) => {
  const { token } = req.params;

  try {
    const result = await db.query(
      "SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()",
      [token],
    );

    if (result.rows.length > 0) {
      res.render("resetPassword.ejs", { token: token });
    } else {
      res.status(400).render("forgetPassword.ejs", {
        message:
          "The reset link is invalid or has expired. Please request a new one.",
      });
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/manager/delete-menu/:id", async (req, res) => {
  if (!req.user) return res.redirect("/login");

  const itemId = req.params.id;

  try {
    const resResult = await db.query(
      "SELECT id FROM restaurants WHERE owner_id = $1",
      [req.user.id],
    );

    if (resResult.rows.length > 0) {
      const restaurantId = resResult.rows[0].id;

      await db.query("DELETE FROM menus WHERE id = $1 AND restaurant_id = $2", [
        itemId,
        restaurantId,
      ]);
    }

    res.redirect("/manager/menuManagement");
  } catch (err) {
    console.error("Delete Error:", err.message);
    res.status(500).send("Could not delete item.");
  }
});

app.delete("/admin/delete-restaurant/:id", async (req, res) => {
  if (!req.isAuthenticated() || req.user.role?.toLowerCase() !== "admin") {
    return res.status(403).json({ success: false, message: "Unauthorized" });
  }

  const restaurantId = req.params.id;

  try {
    const restaurant = await db.query(
      "SELECT name FROM restaurants WHERE id = $1",
      [restaurantId],
    );

    if (restaurant.rows.length === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Restaurant not found" });
    }

    await db.query("DELETE FROM restaurants WHERE id = $1", [restaurantId]);

    res.json({
      success: true,
      message: `Restaurant ${restaurant.rows[0].name} deleted successfully.`,
    });
  } catch (err) {
    console.error("Delete Error:", err);
    res.status(500).json({ success: false, message: "Database error" });
  }
});

app.delete("/admin/delete-user/:id", async (req, res) => {
  if (req.user.role !== "admin") return res.sendStatus(403);

  try {
    await db.query("DELETE FROM users WHERE id = $1", [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

app.post("/admin/verify-restaurant/:id", async (req, res) => {
  if (req.isAuthenticated() && req.user.role?.toLowerCase() === "admin") {
    const { id } = req.params;
    const { action } = req.body;

    try {
      await db.query("UPDATE restaurants SET status = $1 WHERE id = $2", [
        action,
        id,
      ]);

      res.redirect("/admin/verification");
    } catch (err) {
      console.error(err);
      res.status(500).send("Action failed");
    }
  } else {
    res.status(403).send("Unauthorized");
  }
});

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  try {
    const userCheck = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (userCheck.rows.length === 0) {
      return res.render("forgetPassword.ejs", { message: "Email not found." });
    }

    const token = crypto.randomBytes(20).toString("hex");
    const expires = new Date(Date.now() + 3600000);

    await db.query(
      "UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE email = $3",
      [token, expires, email],
    );

    const resetLink = `http://localhost:3000/resetPassword/${token}`;

    console.log("RESET LINK:", resetLink);

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "SwiftBite Password Reset",
      html: `
  <p>Hello,</p>
  <p>We received a request to reset the password for your SwiftBite account.</p>
  <p>Please click the link below to set a new password:</p>
  <p><a href="${resetLink}" style="color: #e67e22; font-weight: bold;">Reset My Password</a></p>
  <p>If you did not request this, you can safely ignore this email.</p>
`,
    };

    await transporter.sendMail(mailOptions);
    res.render("index.ejs", {
      message: "Check your email for the reset link.",
    });
  } catch (err) {
    console.error(err);
    res.render("forgetPassword.ejs", {
      message: "Error sending email. Try again later.",
    });
  }
});

app.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.render("resetPassword.ejs", {
      token,
      message: "Passwords do not match.",
    });
  }

  try {
    const hash = await bcrypt.hash(password, 10);

    const result = await db.query(
      "UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL WHERE reset_token = $2 AND reset_token_expires > NOW() RETURNING *",
      [hash, token],
    );

    if (result.rows.length > 0) {
      res.render("index.ejs", {
        message: "Password updated successfully. You can now log in.",
      });
    } else {
      res.status(400).render("forgotPassword.ejs", {
        message:
          "This link is invalid or has expired. Please request a new one.",
      });
    }
  } catch (err) {
    console.error("Reset Password Error:", err);
    res.status(500).send("Internal Server Error.");
  }
});

app.post("/set-role", async (req, res) => {
  const role = req.body.role.toLowerCase();
  try {
    await db.query("UPDATE users SET role = $1 WHERE id = $2", [
      role,
      req.user.id,
    ]);
    req.user.role = role;
    res.redirect("/dashboard");
  } catch (err) {
    console.error("this", err);
    console.log("This", err);
    res.redirect("/dashboard");
  }
});

app.post("/admin/withdraw", async (req, res) => {
  if (!req.isAuthenticated() || req.user.role !== "admin") {
    return res.status(403).json({ error: "Unauthorized access" });
  }

  const { amount, method } = req.body;
  console.log(amount, method);

  try {
    const result = await db.query(
      "SELECT SUM(total_price * 0.25) as earnings FROM orders WHERE status = 'completed'",
    );
    const availableBalance = result.rows[0].earnings || 0;

    if (parseFloat(amount) > availableBalance) {
      return res
        .status(400)
        .json({ error: "Insufficient funds in your 25% commission pool." });
    }

    if (parseFloat(amount) <= 0) {
      return res.status(400).json({ error: "Invalid amount." });
    }

    res.status(200).json({
      message: `Withdrawal request for NLe ${amount} via ${method} has been submitted.`,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error during withdrawal." });
  }
});

app.get("/admin/withdrawal-history", async (req, res) => {
  try {
    const result = await db.query(
      "SELECT amount, method, status, created_at FROM withdrawals ORDER BY created_at DESC",
    );

    res.json({ success: true, history: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

app.get("/admin/settings", async (req, res) => {
  if (req.isAuthenticated() && req.user.role?.toLowerCase() === "admin") {
    try {
      const result = await db.query("SELECT * FROM users WHERE id = $1", [
        req.user.id,
      ]);
      const adminData = result.rows[0];

      res.render("admin/settings.ejs", {
        currentPage: "settings",
        user: adminData,
      });
    } catch (err) {
      console.error(err);
      res.redirect("/admin/dashboard");
    }
  } else {
    res.redirect("/login");
  }
});

// app.get("/manager/staffManagement", (req, res) => {
//   res.render("manager/staffManagement.ejs");
// });

app.get("/manager/staffManagement", async (req, res) => {
  if (!req.user) return res.redirect("/login");

  try {
    const resResult = await db.query(
      "SELECT id FROM restaurants WHERE owner_id = $1",
      [req.user.id],
    );
    if (resResult.rows.length === 0) return res.redirect("/manager/apply");

    const restaurantId = resResult.rows[0].id;
    const staffResult = await db.query(
      "SELECT id, full_name, email, role FROM staff WHERE restaurant_id = $1",
      [restaurantId],
    );

    res.render("manager/staffManagement.ejs", {
      staffMembers: staffResult.rows,
      restaurantId: resResult.rows[0].id,
      currentPage: "staffManagement",
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Database Error");
  }
});

app.get("/manager/orders", async (req, res) => {
  try {
    const resResult = await db.query(
      "SELECT id FROM restaurants WHERE owner_id = $1",
      [req.user.id],
    );
    const restaurantId = resResult.rows[0].id;

    const ordersResult = await db.query(
      "SELECT * FROM orders WHERE restaurant_id = $1 AND status != 'completed' ORDER BY created_at DESC",
      [restaurantId],
    );

    res.render("manager/ordingTracking.ejs", {
      orders: ordersResult.rows,
      currentPage: "orders",
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error loading orders");
  }
});

app.get("/manager/order-history", async (req, res) => {
  if (!req.user) return res.redirect("/login");

  try {
    const resResult = await db.query(
      "SELECT id FROM restaurants WHERE owner_id = $1",
      [req.user.id],
    );
    const restaurantId = resResult.rows[0].id;

    const historyResult = await db.query(
      "SELECT * FROM orders WHERE restaurant_id = $1 AND status = 'completed' ORDER BY created_at DESC",
      [restaurantId],
    );

    res.render("manager/orderHistory.ejs", {
      orders: historyResult.rows,
      currentPage: "order-history",
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error loading order history.");
  }
});

app.get("/manager/revenue", async (req, res) => {
  if (!req.user) return res.redirect("/login");

  try {
    const resResult = await db.query(
      "SELECT id FROM restaurants WHERE owner_id = $1",
      [req.user.id],
    );

    if (resResult.rows.length === 0) {
      return res.render("manager/revenue.ejs", {
        totalBalance: "0.00",
        totalCompleted: 0,
        history: [],
        restaurantId: null,
      });
    }

    const restaurantId = resResult.rows[0].id;

    const statsQuery = await db.query(
      "SELECT COALESCE(SUM(total_price), 0) as total_earned, COUNT(id) as total_completed FROM orders WHERE restaurant_id = $1 AND status = 'completed'",
      [restaurantId],
    );

    const totalEarned = parseFloat(statsQuery.rows[0].total_earned);
    const totalCompleted = statsQuery.rows[0].total_completed;

    const withdrawnQuery = await db.query(
      "SELECT COALESCE(SUM(amount), 0) as total FROM withdrawals WHERE restaurant_id = $1 AND status != 'rejected'",
      [restaurantId],
    );
    const totalWithdrawn = parseFloat(withdrawnQuery.rows[0].total);

    const availableBalance = (totalEarned - totalWithdrawn).toFixed(2);

    const history = await db.query(
      "SELECT * FROM withdrawals WHERE restaurant_id = $1 ORDER BY created_at DESC",
      [restaurantId],
    );

    res.render("manager/revenue.ejs", {
      totalBalance: availableBalance,
      totalCompleted: totalCompleted,
      history: history.rows,
      restaurantId: restaurantId,
      currentPage: "revenue",
    });
  } catch (err) {
    console.error("Revenue Error:", err.message);
    res.status(500).send("Error loading revenue data.");
  }
});

app.get("/manager/settings", async (req, res) => {
  if (!req.user) return res.redirect("/login");

  try {
    const result = await db.query(
      `SELECT u.full_name, u.email, u.profile_image, r.name AS res_name, r.image_url, r.address, r.contact_number 
     FROM users u 
     LEFT JOIN restaurants r ON u.id = r.owner_id 
     WHERE u.id = $1`,
      [req.user.id],
    );

    const userData = result.rows[0];
    console.log(userData);
    const displayData = {
      full_name: userData.full_name || "New Manager",
      email: userData.email || "",
      res_name: userData.res_name || "My Restaurant",
      image_url: userData.image_url || "/images/default-restaurant.png",
      address: userData.address,
      contact_number: userData.contact_number,
      profile_image:
        userData.profile_image || "/images/IMG-20260112-WA0038.jpg",
      currentPage: "settings",
    };

    res.render("manager/settings.ejs", {
      user: displayData,
      currentPage: "settings",
    });
  } catch (err) {
    console.error("Database Error:", err.message);
    res.status(500).send("Error loading settings.");
  }
});

app.post("/manager/update-profile", async (req, res) => {
  const { full_name, email, password } = req.body;
  try {
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      await db.query(
        "UPDATE users SET full_name = $1, email = $2, password_hash = $3 WHERE id = $4",
        [full_name, email, hashedPassword, req.user.id],
      );
    } else {
      await db.query(
        "UPDATE users SET full_name = $1, email = $2 WHERE id = $3",
        [full_name, email, req.user.id],
      );
    }
    res.redirect("/manager/settings?success=profile");
  } catch (err) {
    res.status(500).send("Error updating profile.");
  }
});

app.post(
  "/manager/update-restaurant",
  upload.single("image"),
  async (req, res) => {
    const { resName, contactNumber, address } = req.body;
    const userId = req.user.id;

    const imageUrl = req.file ? `/uploads/menu/${req.file.filename}` : null;

    try {
      await db.query(
        `INSERT INTO restaurants (owner_id, name, contact_number, address, image_url)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (owner_id)
             DO UPDATE SET name = $2, contact_number = $3, address = $4, image_url = $5`,
        [userId, resName, contactNumber, address, imageUrl],
      );
      res.redirect("/manager/settings?success=restaurant");
    } catch (err) {
      console.error(err);
      res.status(500).send("Update failed");
    }
  },
);

app.post("/manager/withdraw", async (req, res) => {
  if (!req.user) return res.redirect("/login");

  const { amount, method, restaurantId, phone } = req.body;

  try {
    await db.query(
      "INSERT INTO withdrawals (restaurant_id, amount, method, status, phone, created_at) VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)",
      [restaurantId, amount, method, "pending", phone],
    );

    res.redirect("/manager/revenue");
  } catch (err) {
    console.error("Database Error:", err);
    res.status(500).send("Transaction failed. Please try again.");
  }
});

app.post("/manager/update-order/:id", async (req, res) => {
  const orderId = req.params.id;
  const { status } = req.body;

  try {
    await db.query("UPDATE orders SET status = $1 WHERE id = $2", [
      status,
      orderId,
    ]);
    res.redirect("/manager/orders");
  } catch (err) {
    console.error(err);
    res.status(500).send("Failed to update order status");
  }
});

app.post("/manager/add-staff", async (req, res) => {
  const { fullName, email, password, role, restaurantId } = req.body;
  console.log(fullName, email, password, role);
  console.log("Adding staff for Restaurant ID:", restaurantId);

  try {
    const hashedPassword = await bcrypt.hash(password, saltRound);

    await db.query(
      "INSERT INTO staff (restaurant_id, full_name, email, password_hash, role) VALUES ($1, $2, $3, $4, $5)",
      [restaurantId, fullName, email, hashedPassword, "staff"],
    );

    res.redirect("/manager/staffManagement");
  } catch (err) {
    if (err.code === "23505") {
      req.flash("error", "User with that email is already taken.");
      return res.redirect("/manager/staffManagement");
    }
    res.status(500).send("Error adding staff.");
  }
});

app.post("/manager/delete-staff/:id", async (req, res) => {
  const staffId = req.params.id;
  try {
    await db.query("DELETE FROM staff WHERE id = $1", [staffId]);
    res.redirect("/manager/staffManagement");
  } catch (err) {
    res.status(500).send("Error removing staff.");
  }
});

app.post("/admin/update-profile", async (req, res) => {
  if (req.isAuthenticated() && req.user.role?.toLowerCase() === "admin") {
    const { fullName, email } = req.body;

    try {
      await db.query(
        "UPDATE users SET full_name = $1, email = $2 WHERE id = $3",
        [fullName, email, req.user.id],
      );

      req.user.full_name = fullName;
      req.user.email = email;

      io.emit("profileUpdated", {
        fullName: fullName,
        email: email,
      });

      return res.json({ success: true, message: "Profile updated" });
    } catch (err) {
      console.error(err);
      return res
        .status(500)
        .json({ success: false, message: "Error updating profile." });
    }
  } else {
    return res.status(403).json({ success: false, message: "Unauthorized" });
  }
});

app.post("/admin/change-password", async (req, res) => {
  if (req.isAuthenticated() && req.user.role?.toLowerCase() === "admin") {
    const { newPassword, confirmPassword } = req.body;

    if (newPassword !== confirmPassword) {
      return res
        .status(400)
        .json({ success: false, message: "Passwords do not match." });
    }

    try {
      const hash = await bcrypt.hash(newPassword, saltRound);
      await db.query("UPDATE users SET password_hash = $1 WHERE id = $2", [
        hash,
        req.user.id,
      ]);
      return res.json({
        success: true,
        message: "Password updated successfully.",
      });
    } catch (err) {
      console.error(err);
      return res
        .status(500)
        .json({ success: false, message: "Error updating password." });
    }
  } else {
    return res.status(403).json({ success: false, message: "Unauthorized" });
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    failureRedirect: "/login",
    failureFlash: true,
  }),
  (req, res) => {
    // If the user came from the 'staff' table, send them to staff dashboard
    if (req.user.tableType === "staff") {
      return res.redirect("/staff/dashboard");
    }

    // Otherwise, check roles for managers/admins
    const role = req.user.role?.toLowerCase();
    if (role === "admin") return res.redirect("/admin/dashboard");
    if (role === "manager") return res.redirect("/manager/dashboard");

    res.redirect("/choose-role");
  },
);

app.post("/register", async (req, res) => {
  const { fullname, email, password, role } = req.body;
  console.log(fullname, email, password, role);

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (result.rows.length > 0) {
      res.render("index.ejs", {
        message: "The user you want to register already exist.",
      });
    } else {
      bcrypt.hash(password, saltRound, async (err, hash) => {
        if (err) {
          res.status(500).send("Error creating account");
        } else {
          try {
            const newUser = await db.query(
              "INSERT INTO users(full_name, email, password_hash, role) VALUES($1, $2, $3, $4) RETURNING *",
              [fullname, email, hash, role],
            );

            const countRes = await db.query("SELECT COUNT(*) FROM users");
            const totalUsers = countRes.rows[0].count;

            io.emit("update-user-count", {
              total: totalUsers,
              name: fullname,
            });

            const user = newUser.rows[0];
            console.log(user);

            req.login(user, (err) => {
              if (err) {
                res.redirect("/login");
              } else {
                res.redirect("/dashboard");
              }
            });
          } catch (dbErr) {
            res.status(500).send("Error creating account");
          }
        }
      });
    }
  } catch (err) {
    res.status(500).send("Error processing request");
  }
});

passport.use(
  "local",
  new Strategy({ usernameField: "email" }, async function verify(
    email,
    password,
    cb,
  ) {
    try {
      // Look in both tables. We use ::TEXT to ensure UUIDs and Integers don't clash.
      const query = `
        SELECT id::TEXT, email, password_hash, role, 'users' AS table_type FROM users WHERE email = $1
        UNION ALL
        SELECT id::TEXT, email, password_hash, role, 'staff' AS table_type FROM staff WHERE email = $1
        LIMIT 1
      `;
      const result = await db.query(query, [email]);
      const user = result.rows[0];

      if (!user) return cb(null, false, { message: "Account not found." });

      bcrypt.compare(password, user.password_hash, (err, valid) => {
        if (err) return cb(err);
        if (valid) {
          // Pass the table_type into the session so we know who is who
          user.tableType = user.table_type;
          return cb(null, user);
        } else {
          return cb(null, false, { message: "Incorrect password." });
        }
      });
    } catch (err) {
      return cb(err);
    }
  }),
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.CLIENTID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/swiftbite",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [
        profile.email,
      ]);

      if (result.rows.length > 0) {
        cb(null, result.rows[0]);
      } else {
        const newUser = await db.query(
          "INSERT INTO users(full_name, email, password_hash, role) VALUES($1, $2, $3, $4) RETURNING *",
          [profile.displayName, profile.email, "google", null],
        );

        const countRes = await db.query("SELECT COUNT(*) FROM users");
        const totalUsers = countRes.rows[0].count;

        io.emit("update-user-count", {
          total: totalUsers,
          name: profile.displayName,
        });

        return cb(null, newUser.rows[0]);
      }
    },
  ),
);

passport.serializeUser((user, cb) => {
  cb(null, { id: user.id, type: user.tableType });
});

passport.deserializeUser(async (obj, cb) => {
  try {
    const table = obj.type === "staff" ? "staff" : "users";
    const result = await db.query(
      `SELECT * FROM ${table} WHERE id::text = $1`,
      [obj.id],
    );
    const user = result.rows[0];
    if (user) user.tableType = obj.type;
    cb(null, user);
  } catch (err) {
    cb(err);
  }
});

server.listen(port, () => {
  console.log(`The server is running on port ${port}`);
});
