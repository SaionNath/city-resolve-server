const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ObjectId, ServerApiVersion } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET);
const admin = require("firebase-admin");

const app = express();
// const port = process.env.PORT || 3000;
module.exports = app;
const crypto = require("crypto");
const PDFDocument = require("pdfkit");

// const serviceAccount = require("./city-resolve-client-firebase-adminsdk.json");

const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf8",
);
const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

function generateTrackingId() {
  const prefix = "CRV";
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const random = crypto.randomBytes(3).toString("hex").toUpperCase();

  return `${prefix}-${date}-${random}`;
}

app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.ulrflcx.mongodb.net/?retryWrites=true&w=majority`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  await client.connect();
  const db = client.db("city_resolve_db");

  const users = db.collection("users");
  const issues = db.collection("issues");
  const timelines = db.collection("timelines");
  const payments = db.collection("payments");
  const staffRequests = db.collection("staff_requests");

  const verifyToken = async (req, res, next) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).send({ message: "Unauthorized" });

    try {
      const token = auth.split(" ")[1];
      const decodedUser = await admin.auth().verifyIdToken(token);

      req.email = decodedUser.email;

      const dbUser = await users.findOne({ email: req.email });
      if (!dbUser) {
        return res.status(403).send({ message: "User not found in DB" });
      }

      req.role = dbUser.role;

      next();
    } catch (err) {
      console.error("verifyToken error:", err);
      res.status(401).send({ message: "Unauthorized" });
    }
  };

  //role guard
  const verifyRole = (role) => async (req, res, next) => {
    if (req.role !== role) {
      return res.status(403).send({ message: "Forbidden" });
    }
    next();
  };

  //timeline logger
  const logTimeline = async (issueId, trackingId, status, message, by) => {
    await timelines.insertOne({
      issueId: new ObjectId(issueId),
      trackingId,
      status,
      message,
      updatedBy: by,
      createdAt: new Date(),
    });
  };

  //Users
  app.post("/users", async (req, res) => {
    const user = req.body;
    const exists = await users.findOne({ email: user.email });
    if (exists) return res.send({ message: "User exists" });

    user.role = "citizen";
    user.isPremium = false;
    user.isBlocked = false;
    user.createdAt = new Date();

    res.send(await users.insertOne(user));
  });

  app.get("/users", verifyToken, verifyRole("admin"), async (req, res) => {
    try {
      const { search } = req.query;
      const query = {};
      if (search) {
        query.$or = [
          { displayName: { $regex: search, $options: "i" } },
          { email: { $regex: search, $options: "i" } },
        ];
      }
      const result = await users.find(query).sort({ createdAt: -1 }).toArray();
      res.send(result);
    } catch (error) {
      console.error(error);
      res.status(500).send({ message: "Server error" });
    }
  });

  app.get("/users/role/:email", async (req, res) => {
    const email = req.params.email;
    const user = await users.findOne({ email });
    if (!user) return res.status(404).send({ message: "User not found" });
    res.send({ role: user.role });
  });

  app.get("/users/:email", async (req, res) => {
    const email = req.params.email;
    try {
      const user = await users.findOne({ email });
      if (!user) return res.status(404).send({ message: "User not found" });
      res.send(user);
    } catch (error) {
      console.error(error);
      res.status(500).send({ message: "Server error" });
    }
  });

  app.patch(
    "/users/:id/block",
    verifyToken,
    verifyRole("admin"),
    async (req, res) => {
      try {
        const userId = req.params.id;
        const { isBlocked } = req.body;

        const result = await users.updateOne(
          { _id: new ObjectId(userId) },
          { $set: { isBlocked } },
        );

        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Server error" });
      }
    },
  );

  app.patch(
    "/users/:id/role",
    verifyToken,
    verifyRole("admin"),
    async (req, res) => {
      try {
        const userId = req.params.id;
        const { action } = req.body;

        const user = await users.findOne({ _id: new ObjectId(userId) });
        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }

        if (req.email === user.email) {
          return res
            .status(400)
            .send({ message: "You cannot change your own role" });
        }

        //promote to admin
        if (action === "promote") {
          if (user.role === "admin") {
            return res.status(400).send({ message: "Already admin" });
          }

          await users.updateOne(
            { _id: new ObjectId(userId) },
            {
              $set: {
                role: "admin",
                previousRole: user.role,
              },
            },
          );

          return res.send({ success: true, action: "promoted" });
        }

        //demote admin
        if (action === "demote") {
          const restoreRole = user.previousRole;

          await users.updateOne(
            { _id: new ObjectId(userId) },
            {
              $set: { role: restoreRole },
              $unset: { previousRole: "" },
            },
          );

          return res.send({ success: true, action: "demoted" });
        }

        return res.status(400).send({ message: "Invalid role change" });
      } catch (error) {
        console.error("Role update error:", error);
        res.status(500).send({ message: "Server error" });
      }
    },
  );

  app.patch("/users/profile", verifyToken, async (req, res) => {
    try {
      const { displayName, photoURL } = req.body;

      if (!displayName && !photoURL) {
        return res.status(400).send({ message: "Nothing to update" });
      }

      const updateDoc = {};
      if (displayName) updateDoc.displayName = displayName;
      if (photoURL) updateDoc.photoURL = photoURL;

      await users.updateOne({ email: req.email }, { $set: updateDoc });

      const fbUser = await admin.auth().getUserByEmail(req.email);
      await admin.auth().updateUser(fbUser.uid, updateDoc);

      res.send({ success: true });
    } catch (error) {
      console.error("Profile update error:", error);
      res.status(500).send({ message: "Server error" });
    }
  });

  //staff
  app.get("/staffs", verifyToken, verifyRole("admin"), async (req, res) => {
    const result = await users
      .find({ role: "staff" })
      .sort({ createdAt: -1 })
      .toArray();

    res.send(result);
  });

  app.get(
    "/staffs/available",
    verifyToken,
    verifyRole("admin"),
    async (req, res) => {
      const { district } = req.query;
      if (!district)
        return res.status(400).send({ message: "District required" });

      const busyStaff = await issues
        .aggregate([
          { $match: { isActiveAssignment: true } },
          {
            $group: {
              _id: "$assignedStaff.staffEmail",
            },
          },
        ])
        .toArray();

      const busyStaffEmails = busyStaff.map((s) => s._id);

      const staff = await users
        .find({
          role: "staff",
          isBlocked: false,
          staffDistrict: district,
          email: { $nin: busyStaffEmails },
        })
        .toArray();

      res.send(staff);
    },
  );

  // app.post("/staffs", verifyToken, async (req, res) => {
  //   try {
  //     const data = req.body;

  //     const exists = await staffRequests.findOne({
  //       staffEmail: req.email,
  //       status: "pending",
  //     });

  //     if (exists) {
  //       return res.status(400).send({ message: "Request already submitted" });
  //     }

  //     const staffRequest = {
  //       ...data,
  //       staffEmail: req.email,
  //       status: "pending",
  //       requestedAt: new Date(),
  //     };

  //     const result = await staffRequests.insertOne(staffRequest);
  //     res.send(result);
  //   } catch (error) {
  //     console.error(error);
  //     res.status(500).send({ message: "Server error" });
  //   }
  // });

  // app.patch(
  //   "/staffs/approve/:id",
  //   verifyToken,
  //   verifyRole("admin"),
  //   async (req, res) => {
  //     const requestId = req.params.id;

  //     const request = await staffRequests.findOne({
  //       _id: new ObjectId(requestId),
  //     });

  //     if (!request || request.status !== "pending") {
  //       return res.status(400).send({ message: "Invalid request" });
  //     }

  //     await users.updateOne(
  //       { email: request.staffEmail },
  //       {
  //         $set: {
  //           role: "staff",
  //           staffDistrict: request.staffDistrict,
  //           staffRegion: request.staffRegion,
  //           staffName: request.staffName,
  //         },
  //       }
  //     );

  //     await staffRequests.updateOne(
  //       { _id: new ObjectId(requestId) },
  //       {
  //         $set: {
  //           status: "approved",
  //           approvedAt: new Date(),
  //         },
  //       }
  //     );

  //     res.send({ success: true, message: "Staff approved" });
  //   }
  // );

  // app.patch(
  //   "/staffs/reject/:id",
  //   verifyToken,
  //   verifyRole("admin"),
  //   async (req, res) => {
  //     const requestId = req.params.id;

  //     await staffRequests.updateOne(
  //       { _id: new ObjectId(requestId) },
  //       {
  //         $set: {
  //           status: "rejected",
  //           rejectedAt: new Date(),
  //         },
  //       }
  //     );

  //     res.send({ success: true, message: "Staff request rejected" });
  //   }
  // );

  //staff creation
  app.post(
    "/admin/create-staff",
    verifyToken,
    verifyRole("admin"),
    async (req, res) => {
      try {
        const {
          staffName,
          staffEmail,
          password,
          staffAge,
          staffPhone,
          staffNid,
          staffRegion,
          staffDistrict,
          photoURL,
        } = req.body;

        const userRecord = await admin.auth().createUser({
          email: staffEmail,
          password,
          displayName: staffName,
          photoURL,
        });

        const staffUser = {
          email: staffEmail,
          displayName: staffName,
          photoURL,
          role: "staff",
          staffName,
          staffRegion,
          staffDistrict,
          staffPhone,
          staffAge,
          staffNid,
          isPremium: false,
          isBlocked: false,
          createdAt: new Date(),
        };

        await users.insertOne(staffUser);

        res.send({ success: true });
      } catch (error) {
        console.error("Create staff error:", error);
        res.status(500).send({ message: error.message });
      }
    },
  );

  app.get(
    "/admin/payments",
    verifyToken,
    verifyRole("admin"),
    async (req, res) => {
      const result = await payments
        .aggregate([
          {
            $lookup: {
              from: "issues",
              localField: "issueId",
              foreignField: "_id",
              as: "issue",
            },
          },
          { $unwind: { path: "$issue", preserveNullAndEmptyArrays: true } },
          {
            $project: {
              email: 1,
              amount: 1,
              currency: 1,
              transactionId: 1,
              paidAt: 1,
              paymentStatus: 1,
              type: 1,
              trackingId: 1,
              issueTitle: "$issue.title",
              reason: {
                $cond: [
                  { $eq: ["$type", "premium"] },
                  "Premium Membership",
                  "Issue Priority Boost",
                ],
              },
            },
          },
        ])
        .sort({ paidAt: -1 })
        .toArray();

      res.send(result);
    },
  );

  app.get(
    "/admin/payments/:id/receipt",
    verifyToken,
    verifyRole("admin"),
    async (req, res) => {
      const payment = await payments.findOne({
        _id: new ObjectId(req.params.id),
      });

      if (!payment)
        return res.status(404).send({ message: "Payment not found" });

      const doc = new PDFDocument();

      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", "attachment; filename=receipt.pdf");

      doc.pipe(res);

      doc
        .fontSize(20)
        .text("City Resolve Payment Receipt", { align: "center" });
      doc.moveDown();

      doc.fontSize(12).text(`Transaction ID: ${payment.transactionId}`);
      doc.text(`Email: ${payment.email}`);
      doc.text(`Amount: ${payment.amount} ${payment.currency}`);
      doc.text(`Date: ${new Date(payment.paidAt).toLocaleString()}`);

      if (payment.type === "premium") {
        doc.text("Reason: Premium Membership Purchase");
      } else {
        doc.text("Reason: Issue Priority Boost");
        doc.text(`Tracking ID: ${payment.trackingId}`);
      }

      doc.end();
    },
  );

  //issues
  app.post("/issues", verifyToken, async (req, res) => {
    try {
      const reporter = await users.findOne({ email: req.email });

      if (!reporter) {
        return res.status(404).send({ message: "User not found" });
      }

      if (reporter.role === "citizen" && !reporter.isPremium) {
        const issueCount = await issues.countDocuments({
          reporterEmail: req.email,
        });

        if (issueCount >= 3) {
          await users.updateOne(
            { email: req.email },
            {
              $set: {
                isBlocked: true,
                blockReason: "Free users can report only 3 issues",
              },
            },
          );

          return res.status(403).send({
            code: "FREE_LIMIT_REACHED",
            reason: "Free users can report only 3 issues",
          });
        }
      }

      const issue = req.body;

      issue.status = "pending";
      issue.priority = "normal";
      issue.upvotes = [];
      issue.createdAt = new Date();
      issue.trackingId = generateTrackingId();
      issue.reporterEmail = req.email;

      const result = await issues.insertOne(issue);

      await timelines.insertOne({
        issueId: result.insertedId,
        trackingId: issue.trackingId,
        status: "pending",
        message: "Issue reported",
        updatedBy: "Citizen",
        createdAt: new Date(),
      });

      res.send({
        insertedId: result.insertedId,
        trackingId: issue.trackingId,
      });
    } catch (error) {
      console.error(error);
      res.status(500).send({ message: "Server error" });
    }
  });

  app.get("/issues/home", async (req, res) => {
    try {
      const result = await issues
        .aggregate([
          {
            $match: {
              status: {
                $in: ["approved", "assigned", "in-progress"],
              },
            },
          },
          {
            $addFields: {
              upvoteCount: { $size: { $ifNull: ["$upvotes", []] } },
              priorityWeight: {
                $cond: [{ $eq: ["$priority", "high"] }, 1, 0],
              },
            },
          },
          {
            $sort: {
              priorityWeight: -1,
              upvoteCount: -1,
              createdAt: -1,
            },
          },
          {
            $limit: 6,
          },
        ])
        .toArray();

      res.send(result);
    } catch (error) {
      console.error("Home issues error:", error);
      res.status(500).send({ message: "Server error" });
    }
  });

  app.get(
    "/issues/completed",
    verifyToken,
    verifyRole("staff"),
    async (req, res) => {
      try {
        const result = await issues
          .find({
            "assignedStaff.staffEmail": req.email,
            status: { $in: ["resolved", "closed"] },
          })
          .sort({ updatedAt: -1, createdAt: -1 })
          .toArray();

        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Server error" });
      }
    },
  );

  app.get("/issues", verifyToken, async (req, res) => {
    const { status, category, priority, search, assignedToMe, includePending } =
      req.query;

    const matchQuery = {
      status: { $ne: "pending" },
    };

    if (req.role === "admin" && req.query.includePending === "true") {
      delete matchQuery.status;
    }

    if (status) matchQuery.status = status;
    if (category) matchQuery.category = category;
    if (priority) matchQuery.priority = priority;

    if (search) {
      matchQuery.$or = [
        { title: { $regex: search, $options: "i" } },
        { location: { $regex: search, $options: "i" } },
      ];
    }

    if (assignedToMe === "true") {
      matchQuery["assignedStaff.staffEmail"] = req.email;
      matchQuery.status = { $in: ["assigned", "in-progress", "resolved"] };
    }

    const result = await issues
      .aggregate([
        { $match: matchQuery },
        {
          $addFields: {
            upvoteCount: { $size: { $ifNull: ["$upvotes", []] } },
            priorityWeight: {
              $cond: [{ $eq: ["$priority", "high"] }, 1, 0],
            },
          },
        },
        {
          $sort: {
            priorityWeight: -1,
            upvoteCount: -1,
            createdAt: -1,
          },
        },
      ])
      .toArray();

    res.send(result);
  });

  app.get("/issues/my", verifyToken, async (req, res) => {
    try {
      const email = req.email;

      const result = await issues
        .find({ reporterEmail: email })
        .sort({ createdAt: -1 })
        .toArray();

      res.send(result);
    } catch (error) {
      console.error(error);
      res.status(500).send({ message: "Server error" });
    }
  });

  app.get("/issues/:id", verifyToken, async (req, res) => {
    res.send(await issues.findOne({ _id: new ObjectId(req.params.id) }));
  });

  app.patch(
    "/issues/:id/approve",
    verifyToken,
    verifyRole("admin"),
    async (req, res) => {
      const issueId = req.params.id;

      const issue = await issues.findOne({ _id: new ObjectId(issueId) });
      if (!issue) {
        return res.status(404).send({ message: "Issue not found" });
      }

      if (issue.status !== "pending") {
        return res.status(400).send({ message: "Issue already reviewed" });
      }

      await issues.updateOne(
        { _id: new ObjectId(issueId) },
        { $set: { status: "approved" } },
      );

      await timelines.insertOne({
        issueId: issue._id,
        trackingId: issue.trackingId,
        status: "approved",
        message: "Issue approved by admin",
        updatedBy: "Admin",
        createdAt: new Date(),
      });

      res.send({ success: true });
    },
  );

  app.patch(
    "/issues/:id/reject",
    verifyToken,
    verifyRole("admin"),
    async (req, res) => {
      const issueId = req.params.id;
      const { reason } = req.body;

      if (!reason) {
        return res.status(400).send({ message: "Rejection reason required" });
      }

      const issue = await issues.findOne({ _id: new ObjectId(issueId) });
      if (!issue) {
        return res.status(404).send({ message: "Issue not found" });
      }

      await issues.updateOne(
        { _id: new ObjectId(issueId) },
        {
          $set: {
            status: "rejected",
            rejectionReason: reason,
          },
        },
      );

      await timelines.insertOne({
        issueId: issue._id,
        trackingId: issue.trackingId,
        status: "rejected",
        message: `Issue rejected: ${reason}`,
        updatedBy: "Admin",
        createdAt: new Date(),
      });

      res.send({ success: true });
    },
  );

  app.patch("/issues/:id/edit", verifyToken, async (req, res) => {
    const issueId = req.params.id;
    const email = req.email;
    const updateData = req.body;

    const issue = await issues.findOne({ _id: new ObjectId(issueId) });

    if (!issue) {
      return res.status(404).send({ message: "Issue not found" });
    }

    if (issue.reporterEmail !== email) {
      return res.status(403).send({ message: "Not authorized" });
    }

    if (issue.status !== "pending") {
      return res
        .status(400)
        .send({ message: "Only pending issues can be edited" });
    }

    const { title, description, image, incidentRegion, incidentDistrict } =
      req.body;

    const allowedUpdates = {
      title,
      description,
      image,
      incidentRegion,
      incidentDistrict,
    };

    await issues.updateOne(
      { _id: new ObjectId(issueId) },
      {
        $set: {
          ...allowedUpdates,
          updatedAt: new Date(),
        },
      },
    );

    await timelines.insertOne({
      issueId: issue._id,
      trackingId: issue.trackingId,
      status: "edited",
      message: "Issue edited by reporter",
      updatedBy: "Citizen",
      createdAt: new Date(),
    });

    res.send({ success: true });
  });

  //assign staff
  app.patch(
    "/issues/:id/assign",
    verifyToken,
    verifyRole("admin"),
    async (req, res) => {
      try {
        const { staffEmail, staffName } = req.body;
        const issueId = req.params.id;

        const issue = await issues.findOne({ _id: new ObjectId(issueId) });
        if (!issue) {
          return res.status(404).send({ message: "Issue not found" });
        }

        if (issue.status !== "approved") {
          return res.status(400).send({
            message: "Only approved issues can be assigned",
          });
        }

        const result = await issues.updateOne(
          { _id: new ObjectId(issueId) },
          {
            $set: {
              assignedStaff: { staffEmail, staffName },
              status: "assigned",
              assignedAt: new Date(),
              isActiveAssignment: true,
            },
          },
        );

        if (!result.modifiedCount) {
          return res.status(400).send({ message: "Assignment failed" });
        }

        await logTimeline(
          issueId,
          issue.trackingId,
          "assigned",
          `Assigned to ${staffName}, awaiting acceptance`,
          "Admin",
        );

        res.send({ success: true });
      } catch (error) {
        console.error("Assign staff error:", error);
        res.status(500).send({ message: "Server error" });
      }
    },
  );

  app.patch(
    "/issues/:id/accept",
    verifyToken,
    verifyRole("staff"),
    async (req, res) => {
      const issueId = req.params.id;

      const issue = await issues.findOne({
        _id: new ObjectId(issueId),
        "assignedStaff.staffEmail": req.email,
        status: "assigned",
      });

      if (!issue) {
        return res.status(400).send({ message: "Invalid issue state" });
      }

      if (issue.status !== "assigned") {
        return res.status(400).send({
          message: "Issue already processed",
        });
      }

      await issues.updateOne(
        { _id: issue._id },
        { $set: { status: "in-progress", updatedAt: new Date() } },
      );

      await logTimeline(
        issueId,
        issue.trackingId,
        "in-progress",
        "Issue accepted by staff",
        "Staff",
      );

      res.send({ success: true });
    },
  );

  app.patch(
    "/issues/:id/reject-staff",
    verifyToken,
    verifyRole("staff"),
    async (req, res) => {
      const issueId = req.params.id;
      const { reason } = req.body;

      const issue = await issues.findOne({
        _id: new ObjectId(issueId),
        "assignedStaff.staffEmail": req.email,
        status: "assigned",
      });

      if (!issue) {
        return res.status(400).send({ message: "Invalid issue state" });
      }

      await issues.updateOne(
        { _id: issue._id },
        {
          $unset: { assignedStaff: "" },
          $set: {
            status: "approved",
            isActiveAssignment: false,
            updatedAt: new Date(),
          },
        },
      );

      await timelines.insertOne({
        issueId: issue._id,
        trackingId: issue.trackingId,
        action: "rejected",
        by: "staff",
        staffEmail: req.email,
        reason: reason || "No reason provided",
        at: new Date(),
      });

      res.send({ success: true });
    },
  );

  //status change (staff)
  app.patch(
    "/issues/:id/status",
    verifyToken,
    verifyRole("staff"),
    async (req, res) => {
      const issueId = req.params.id;

      const issue = await issues.findOne({
        _id: new ObjectId(issueId),
        "assignedStaff.staffEmail": req.email,
      });

      if (issue.status !== "in-progress") {
        return res.status(400).send({
          message: "Only in-progress issues can be resolved",
        });
      }

      await issues.updateOne(
        { _id: issue._id },
        {
          $set: {
            status: "resolved",
            resolvedAt: new Date(),
          },
        },
      );

      await logTimeline(
        issueId,
        issue.trackingId,
        "resolved",
        "Issue resolved by staff",
        "Staff",
      );

      res.send({ success: true });
    },
  );

  app.patch(
    "/issues/:id/close",
    verifyToken,
    verifyRole("admin"),
    async (req, res) => {
      const issueId = req.params.id;

      const issue = await issues.findOne({ _id: new ObjectId(issueId) });
      if (!issue) return res.status(404).send({ message: "Issue not found" });

      if (issue.status !== "resolved") {
        return res.status(400).send({ message: "Issue not resolved yet" });
      }

      await issues.updateOne(
        { _id: new ObjectId(issueId) },
        {
          $set: {
            status: "closed",
            isActiveAssignment: false,
          },
        },
      );

      await logTimeline(
        issueId,
        issue.trackingId,
        "closed",
        "Issue closed after admin verification",
        "Admin",
      );

      res.send({ success: true });
    },
  );

  app.delete("/issues/:id", verifyToken, async (req, res) => {
    const issueId = req.params.id;
    const email = req.email;

    const issue = await issues.findOne({ _id: new ObjectId(issueId) });

    if (!issue) {
      return res.status(404).send({ message: "Issue not found" });
    }

    if (issue.reporterEmail !== email) {
      return res.status(403).send({ message: "Not authorized" });
    }

    if (issue.status !== "pending") {
      return res
        .status(400)
        .send({ message: "Only pending issues can be deleted" });
    }

    await issues.deleteOne({ _id: new ObjectId(issueId) });

    await timelines.insertOne({
      issueId: issue._id,
      trackingId: issue.trackingId,
      status: "deleted",
      message: "Issue deleted by reporter",
      updatedBy: "Citizen",
      createdAt: new Date(),
    });

    res.send({ success: true });
  });

  //upvote
  app.patch("/issues/:id/upvote", verifyToken, async (req, res) => {
    const issueId = req.params.id;
    const email = req.email;

    const issue = await issues.findOne({ _id: new ObjectId(issueId) });
    if (!issue) {
      return res.status(404).send({ message: "Issue not found" });
    }

    if (["resolved", "closed"].includes(issue.status)) {
      return res.status(400).send({ message: "Voting closed" });
    }

    if (issue.reporterEmail === email) {
      return res
        .status(403)
        .send({ message: "You cannot upvote your own issue" });
    }

    if (issue.upvotes.includes(email)) {
      return res.status(400).send({ message: "Already upvoted" });
    }

    await issues.updateOne(
      { _id: new ObjectId(issueId) },
      { $push: { upvotes: email } },
    );

    res.send({ success: true });
  });

  //payment api
  app.post("/payment-checkout-session", verifyToken, async (req, res) => {
    try {
      const { issueId, cost } = req.body;
      const issue = await issues.findOne({ _id: new ObjectId(issueId) });

      if (!issue) return res.status(404).send({ message: "Issue not found" });

      if (["resolved", "closed"].includes(issue.status)) {
        return res.status(400).send({
          message: "This issue can no longer be boosted",
        });
      }

      if (issue.priority === "high") {
        return res.status(400).send({
          message: "Already high priority",
        });
      }

      const session = await stripe.checkout.sessions.create({
        line_items: [
          {
            price_data: {
              currency: "bdt",
              unit_amount: cost * 100,
              product_data: {
                name: `Upgrade Issue: ${issue.title} to High Priority`,
              },
            },
            quantity: 1,
          },
        ],
        mode: "payment",
        customer_email: req.email,
        metadata: {
          issueId: issue._id.toString(),
          trackingId: issue.trackingId,
        },
        success_url: `${process.env.SITE_DOMAIN}/dashboard/payment_success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.SITE_DOMAIN}/dashboard/payment_cancel`,
      });

      res.send({ url: session.url });
    } catch (error) {
      console.error(error);
      res.status(500).send({ message: "Server error" });
    }
  });

  app.post("/payment-success", async (req, res) => {
    try {
      const sessionId = req.query.session_id;
      if (!sessionId) {
        return res.status(400).send({ message: "Session ID missing" });
      }

      const session = await stripe.checkout.sessions.retrieve(sessionId);

      if (session.payment_status !== "paid") {
        return res.status(400).send({ message: "Payment not completed" });
      }

      const transactionId = session.payment_intent;

      const paymentExists = await payments.findOne({ transactionId });
      if (paymentExists) {
        return res.send({
          success: true,
          issueId: paymentExists.issueId,
          transactionId,
          trackingId: paymentExists.trackingId,
          message: "Payment already recorded",
        });
      }

      const issueId = session.metadata.issueId;
      const trackingId = session.metadata.trackingId;

      await issues.updateOne(
        { _id: new ObjectId(issueId) },
        { $set: { priority: "high" } },
      );

      const paymentDoc = {
        issueId: new ObjectId(issueId),
        trackingId,
        email: session.customer_email,
        amount: session.amount_total / 100,
        currency: session.currency,
        transactionId,
        paymentStatus: session.payment_status,
        paidAt: new Date(),
      };

      await payments.insertOne(paymentDoc);

      await timelines.insertOne({
        trackingId,
        status: "boosted",
        message: "Issue priority upgraded to high (paid)",
        updatedBy: "Citizen",
        createdAt: new Date(),
      });

      res.send({
        success: true,
        issueId,
        trackingId,
        transactionId,
      });
    } catch (error) {
      console.error("Payment success error:", error);
      res.status(500).send({ success: false, message: "Server error" });
    }
  });

  app.post("/premium-checkout", verifyToken, async (req, res) => {
    const user = await users.findOne({ email: req.email });

    if (!user || user.role !== "citizen") {
      return res.status(403).send({
        message: "Only citizens can upgrade to premium",
      });
    }

    try {
      const session = await stripe.checkout.sessions.create({
        line_items: [
          {
            price_data: {
              currency: "bdt",
              unit_amount: 1000 * 100,
              product_data: {
                name: "City Resolve Premium Membership",
              },
            },
            quantity: 1,
          },
        ],
        mode: "payment",
        customer_email: req.email,
        metadata: {
          type: "premium",
          email: req.email,
        },
        success_url: `${process.env.SITE_DOMAIN}/dashboard/premium_success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.SITE_DOMAIN}/dashboard/premium_cancel`,
      });

      res.send({ url: session.url });
    } catch (error) {
      res.status(500).send({ message: "Server error" });
    }
  });

  app.get("/premium-success", async (req, res) => {
    try {
      const sessionId = req.query.session_id;
      if (!sessionId) {
        return res.status(400).send({ message: "Session ID missing" });
      }

      const session = await stripe.checkout.sessions.retrieve(sessionId);

      if (session.payment_status !== "paid") {
        return res.status(400).send({ message: "Payment not completed" });
      }

      const email = session.metadata.email;
      const transactionId = session.payment_intent;

      const alreadyPaid = await payments.findOne({ transactionId });
      if (alreadyPaid) {
        return res.send({
          success: true,
          message: "Premium already activated",
        });
      }

      await users.updateOne(
        { email },
        {
          $set: {
            isPremium: true,
            isBlocked: false,
            blockReason: null,
          },
        },
      );

      await payments.insertOne({
        email,
        amount: 1000,
        currency: "bdt",
        type: "premium",
        transactionId,
        paidAt: new Date(),
      });

      res.send({ success: true });
    } catch (error) {
      console.error("Premium success error:", error);
      res.status(500).send({ message: "Server error" });
    }
  });

  app.get("/payments", verifyToken, async (req, res) => {
    try {
      const email = req.email;

      const result = await payments
        .find({ email })
        .sort({ paidAt: -1 })
        .toArray();

      res.send(result);
    } catch (error) {
      console.error("Payment history error:", error);
      res.status(500).send({ message: "Server error" });
    }
  });

  //get tracking logs
  app.get("/trackings/:trackingId/logs", async (req, res) => {
    try {
      const { trackingId } = req.params;

      const logs = await timelines
        .find({ trackingId })
        .sort({ createdAt: 1 })
        .toArray();

      res.send(logs);
    } catch (error) {
      console.error("Tracking logs error:", error);
      res.status(500).send({ message: "Server error" });
    }
  });

  //Dashboard statistics
  app.get(
    "/dashboard/admin-stats",
    verifyToken,
    verifyRole("admin"),
    async (req, res) => {
      const usersCount = await users.countDocuments();
      const staffCount = await users.countDocuments({ role: "staff" });
      const citizenCount = await users.countDocuments({ role: "citizen" });

      const issueStats = await issues
        .aggregate([
          {
            $group: {
              _id: "$status",
              count: { $sum: 1 },
            },
          },
        ])
        .toArray();

      res.send({
        usersCount,
        staffCount,
        citizenCount,
        issueStats,
      });
    },
  );

  app.get(
    "/dashboard/staff-stats",
    verifyToken,
    verifyRole("staff"),
    async (req, res) => {
      const assigned = await issues.countDocuments({
        "assignedStaff.staffEmail": req.email,
        status: { $in: ["assigned", "in-progress"] },
      });

      const resolved = await issues.countDocuments({
        "assignedStaff.staffEmail": req.email,
        status: "resolved",
      });

      const closed = await issues.countDocuments({
        "assignedStaff.staffEmail": req.email,
        status: "closed",
      });

      res.send([
        { name: "Assigned", value: assigned },
        { name: "Resolved", value: resolved },
        { name: "Closed", value: closed },
      ]);
    },
  );

  app.get(
    "/dashboard/citizen-stats",
    verifyToken,
    verifyRole("citizen"),
    async (req, res) => {
      const email = req.email;

      const issueStats = await issues
        .aggregate([
          { $match: { reporterEmail: email } },
          {
            $group: {
              _id: "$status",
              count: { $sum: 1 },
            },
          },
        ])
        .toArray();

      const totalIssues = await issues.countDocuments({ reporterEmail: email });

      const totalPayments = await payments.countDocuments({
        email: req.email,
      });

      res.send({
        totalIssues,
        totalPayments,
        statusStats: issueStats,
      });
    },
  );
}

run().catch(console.dir);

app.get("/", (req, res) => res.send("City resolve Server listening"));
app.get("/test", (req, res) => {
  res.send("API working");
});
// app.listen(port, () => console.log(`Server running on port ${port}`));
module.exports = app;
