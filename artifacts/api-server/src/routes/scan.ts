import { Router, type IRouter } from "express";
import {
  ScanTargetBody,
  ScanTargetResponse,
  VerifyOriginBody,
  VerifyOriginResponse,
} from "@workspace/api-zod";
import {
  isPublicIpv4,
  isSafeVerifyPort,
  isValidHostnameForVerification,
  scanTarget,
  verifyOrigin,
} from "../services/recon";

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

  const { hostname, ip, port, useHttps } = parseResult.data;
  const effectivePort = port ?? (useHttps === false ? 80 : 443);

  if (!isValidHostnameForVerification(hostname)) {
    res.status(400).json({ message: "Invalid hostname." });
    return;
  }
  if (!isPublicIpv4(ip)) {
    res.status(400).json({
      message: "IP must be a public, routable IPv4 address. Private/internal/reserved ranges are not allowed.",
    });
    return;
  }
  if (!isSafeVerifyPort(effectivePort)) {
    res.status(400).json({
      message: "Port must be one of the allowed web ports (80, 443, 8080, 8443, 8000, 8888, 8081, 3000).",
    });
    return;
  }

  try {
    const result = await verifyOrigin(hostname, ip, effectivePort, useHttps ?? true);
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
