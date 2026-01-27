const express = require("express");
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const prisma = new PrismaClient();
const app = express();

app.use(cors());
app.use(express.json());

const JWT_SECRET = "SECRET_KEY";
const express = require("express");
console.log("DATABASE_URL exists:", !!process.env.DATABASE_URL);


/* ======================
   AUTH MIDDLEWARE
====================== */
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ error: "Token required" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
};

/* ======================
   BASIC ROUTE
====================== */
app.get("/", (req, res) => {
  res.send("Backend is running 🚀");
});

/* ======================
   AUTH ROUTES
====================== */
app.post("/register", async (req, res) => {
  const { name, email, password, role } = req.body;

  const exists = await prisma.user.findUnique({ where: { email } });
  if (exists) return res.status(400).json({ error: "User already exists" });

  const hashed = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({
    data: { name, email, password: hashed, role },
  });

  res.json({ message: "User created", user });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, {
    expiresIn: "1d",
  });

  res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
});

/* ======================
   TASK ROUTES
====================== */

// AM → Create task
app.post("/tasks", authenticateToken, async (req, res) => {
  if (req.user.role !== "AM") {
    return res.status(403).json({ error: "Only AMs can create tasks" });
  }

  const task = await prisma.task.create({
    data: {
      creatorName: req.body.creatorName,
      taskCategory: req.body.taskCategory,
      taskType: req.body.taskType,
      deadline: req.body.deadline,
      status: "NEW",
    },
  });

  res.json(task);
});

// MANAGER → Assign task
app.patch("/tasks/:id/assign", authenticateToken, async (req, res) => {
  if (req.user.role !== "MANAGER") {
    return res.status(403).json({ error: "Only Managers can assign tasks" });
  }

  const taskId = parseInt(req.params.id);
  const { designerId } = req.body;

  const designer = await prisma.user.findUnique({ where: { id: designerId } });
  if (!designer || designer.role !== "DESIGNER") {
    return res.status(400).json({ error: "Invalid designer" });
  }

  const task = await prisma.task.update({
    where: { id: taskId },
    data: { assignedToId: designerId, status: "ASSIGNED" },
  });

  res.json({ message: "Task assigned", task });
});

// DESIGNER → Update task status
app.patch("/tasks/:id/status", authenticateToken, async (req, res) => {
  if (req.user.role !== "DESIGNER") {
    return res.status(403).json({ error: "Only Designers can update status" });
  }

  const taskId = parseInt(req.params.id);
  const { status } = req.body;

  const task = await prisma.task.findUnique({ where: { id: taskId } });

  if (!task || task.assignedToId !== req.user.id) {
    return res.status(403).json({ error: "Task not assigned to you" });
  }

  const updatedTask = await prisma.task.update({
    where: { id: taskId },
    data: { status },
  });

  res.json({ message: "Status updated", task: updatedTask });
});

// MANAGER or DESIGNER → Reassign task
app.patch("/tasks/:id/reassign", authenticateToken, async (req, res) => {
  const taskId = parseInt(req.params.id);
  const { newDesignerId } = req.body;

  const task = await prisma.task.findUnique({ where: { id: taskId } });
  if (!task) return res.status(404).json({ error: "Task not found" });

  const newDesigner = await prisma.user.findUnique({
    where: { id: newDesignerId },
  });
  if (!newDesigner || newDesigner.role !== "DESIGNER") {
    return res.status(400).json({ error: "Invalid designer" });
  }

  // MANAGER → can reassign any task
  if (req.user.role === "MANAGER") {
    const updatedTask = await prisma.task.update({
      where: { id: taskId },
      data: { assignedToId: newDesignerId },
    });

    return res.json({
      message: "Task reassigned by Manager",
      task: updatedTask,
    });
  }

  // DESIGNER → can reassign only own task
  if (req.user.role === "DESIGNER") {
    if (task.assignedToId !== req.user.id) {
      return res
        .status(403)
        .json({ error: "You can only reassign your own task" });
    }

    const updatedTask = await prisma.task.update({
      where: { id: taskId },
      data: { assignedToId: newDesignerId },
    });

    return res.json({
      message: "Task reassigned by Designer",
      task: updatedTask,
    });
  }

  return res.status(403).json({ error: "Reassignment not allowed" });
});

// VIEW TASKS
app.get("/tasks", authenticateToken, async (req, res) => {
  const tasks = await prisma.task.findMany({
    include: { assignedTo: true },
    orderBy: { createdAt: "desc" },
  });
  res.json(tasks);
});

/* ======================
   START SERVER
====================== */
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
