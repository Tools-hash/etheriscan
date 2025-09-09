const VT_KEY = process.env.VIRUSTOTAL_KEY;

export const config = {
  api: {
    bodyParser: false, // penting biar bisa handle FormData
  },
};

import formidable from "formidable";

export default async function handler(req, res) {
  if (req.method === "POST") {
    // cek apakah ini file upload atau URL scan
    if (req.headers["content-type"]?.includes("multipart/form-data")) {
      // parsing file dari formdata
      const form = formidable({ multiples: false });
      form.parse(req, async (err, fields, files) => {
        if (err) return res.status(500).json({ error: "Upload gagal" });

        const file = files.file;
        const fs = await import("fs");

        const vtRes = await fetch("https://www.virustotal.com/api/v3/files", {
          method: "POST",
          headers: { "x-apikey": process.env.VT_KEY },
          body: fs.createReadStream(file.filepath),
        });

        const data = await vtRes.json();
        return res.status(vtRes.status).json(data);
      });
    } else {
      // kalau bukan file, berarti URL
      const { type, url } = await req.json();
      if (type !== "url") return res.status(400).json({ error: "Invalid request" });

      const vtRes = await fetch("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: {
          "x-apikey": process.env.VT_KEY,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `url=${encodeURIComponent(url)}`,
      });

      const data = await vtRes.json();
      return res.status(vtRes.status).json(data);
    }
  } else {
    return res.status(405).json({ error: "Method Not Allowed" });
  }
}