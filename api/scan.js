// api/scan.js
import formidable from "formidable";

export const config = {
  api: {
    bodyParser: false, // biar bisa handle FormData file
  },
};

const VT_KEY = process.env.VIRUSTOTAL_KEY;

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method Not Allowed" });
  }

  // cek apakah ini file upload (multipart/form-data)
  if (req.headers["content-type"]?.includes("multipart/form-data")) {
    const form = formidable({ multiples: false });

    form.parse(req, async (err, fields, files) => {
      if (err) return res.status(500).json({ error: "Upload gagal" });

      try {
        const file = files.file;
        const fs = await import("fs");

        const vtRes = await fetch("https://www.virustotal.com/api/v3/files", {
          method: "POST",
          headers: { "x-apikey": VT_KEY },
          body: fs.createReadStream(file.filepath),
        });

        const data = await vtRes.json();
        return res.status(vtRes.status).json(data);
      } catch (error) {
        return res.status(500).json({ error: error.message });
      }
    });
  } else {
    try {
      const { type, url } = req.body; // langsung ambil body
      if (type !== "url" || !url) {
        return res.status(400).json({ error: "Invalid request" });
      }

      const vtRes = await fetch("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: {
          "x-apikey": VT_KEY,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `url=${encodeURIComponent(url)}`,
      });

      const data = await vtRes.json();
      return res.status(vtRes.status).json(data);
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  }
}