import { Router, type IRouter } from "express";
import { ScanTargetBody, ScanTargetResponse } from "@workspace/api-zod";
import { scanTarget } from "../services/recon";

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

export default router;
