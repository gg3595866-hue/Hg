import { Router, type IRouter } from "express";
import {
  ScanTargetBody,
  ScanTargetResponse,
  VerifyOriginBody,
  VerifyOriginResponse,
} from "@workspace/api-zod";
import { scanTarget, verifyOrigin } from "../services/recon";

const router: IRouter = Router();

router.post("/scan", async (req, res) => {
  const parseResult = ScanTargetBody.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ message: "Invalid request body." });
    return;
  }

  try {
    const result = await scanTarget(parseResult.data.input);
    const data = ScanTargetResponse.parse(result);
    res.json(data);
  } catch (err) {
    req.log.warn({ err }, "Scan failed");
    res.status(400).json({
      message: err instanceof Error ? err.message : "Scan failed.",
    });
  }
});

router.post("/verify-origin", async (req, res) => {
  const parseResult = VerifyOriginBody.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ message: "Invalid request body." });
    return;
  }

  try {
    const { hostname, ip, port, useHttps } = parseResult.data;
    const result = await verifyOrigin(hostname, ip, port, useHttps);
    const data = VerifyOriginResponse.parse(result);
    res.json(data);
  } catch (err) {
    req.log.warn({ err }, "Origin verification failed");
    res.status(400).json({
      message: err instanceof Error ? err.message : "Origin verification failed.",
    });
  }
});

export default router;
