import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import multer from 'multer';
import ExifParser from 'exif-parser';
import AdmZip from 'adm-zip';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// Mock User Database
interface User {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
}

const users: User[] = [];

// Expanded forensic analysis logic
const SUSPICIOUS_KEYWORDS = [
  "kill", "attack", "bomb", "drug", "weapon", "gun", "shoot", "murder", 
  "steal", "theft", "hack", "scam", "fraud", "threat", "destroy", 
  "explosive", "terror", "illegal", "crime", "victim", "assault"
];

const NEGATIVE_KEYWORDS = ["hate", "angry", "bad", "worst", "stupid", "kill", "die", "hurt"];
const POSITIVE_KEYWORDS = ["good", "love", "great", "excellent", "happy", "thanks", "awesome"];

// Simulated AI Media Classifications
const IMAGE_CLASSIFICATIONS = [
  { 
    trigger: "weapon", 
    label: "High-Risk: Weapon Detected", 
    suspicious: true,
    reason: "Object Recognition: Firearm/Bladed Weapon",
    description: "AI identified a high-probability match for a lethal weapon within the image frame. This constitutes a severe security threat."
  },
  { 
    trigger: "gun", 
    label: "High-Risk: Firearm Detected", 
    suspicious: true,
    reason: "Object Recognition: Firearm",
    description: "AI identified a high-probability match for a lethal firearm within the image frame."
  },
  { 
    trigger: "bomb", 
    label: "High-Risk: Explosive Device Detected", 
    suspicious: true,
    reason: "Object Recognition: Explosive/IED",
    description: "AI identified a high-probability match for a lethal explosive device within the image frame."
  },
  { 
    trigger: "drug", 
    label: "High-Risk: Narcotics Identified", 
    suspicious: true,
    reason: "Visual Analysis: Controlled Substances",
    description: "AI detected packaging and substance characteristics consistent with illegal narcotics. Highly likely to be related to drug trafficking."
  },
  { 
    trigger: "money", 
    label: "Alert: Large Cash Volume", 
    suspicious: true,
    reason: "Pattern Recognition: Bulk Currency",
    description: "Detected large stacks of currency which may indicate money laundering or illicit financial transactions."
  },
  { 
    trigger: "face", 
    label: "Info: Facial Recognition Match", 
    suspicious: false,
    reason: "Biometric Match: Known Associate",
    description: "Facial features match a known contact in the database. No immediate threat detected."
  },
  { 
    trigger: "location", 
    label: "Info: GPS Metadata Found", 
    suspicious: false,
    reason: "Metadata Extraction: Geolocation",
    description: "Image contains embedded GPS coordinates. Location data has been extracted for mapping."
  }
];

const VIDEO_CLASSIFICATIONS = [
  { 
    trigger: "fight", 
    label: "High-Risk: Physical Altercation", 
    suspicious: true,
    reason: "Motion Analysis: Violent Behavior",
    description: "Detected rapid, aggressive movement patterns consistent with a physical fight or assault."
  },
  { 
    trigger: "surveillance", 
    label: "Info: Surveillance Footage", 
    suspicious: false,
    reason: "Context Analysis: Static Camera",
    description: "Video appears to be from a fixed security or surveillance camera."
  },
  { 
    trigger: "transaction", 
    label: "High-Risk: Suspicious Exchange", 
    suspicious: true,
    reason: "Behavioral Analysis: Hand-to-Hand Transfer",
    description: "Detected a quick exchange of small items between individuals, often associated with illicit street-level transactions."
  }
];

function parseChat(text: string) {
  const lines = text.split('\n');
  const messages = [];
  
  for (const line of lines) {
    const trimmedLine = line.trim();
    if (!trimmedLine) continue;
    
    let sender = "Unknown";
    let message = trimmedLine;
    let timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    let attachment = null;
    
    const bracketMatch = trimmedLine.match(/^\[(.*?)\]\s*(.*?):\s*(.*)$/);
    const dashMatch = trimmedLine.match(/^(.*?)\s*-\s*(.*?):\s*(.*)$/);
    const simpleMatch = trimmedLine.match(/^(.*?):\s*(.*)$/);

    if (bracketMatch) {
      timestamp = bracketMatch[1];
      sender = bracketMatch[2];
      message = bracketMatch[3];
    } else if (dashMatch) {
      timestamp = dashMatch[1];
      sender = dashMatch[2];
      message = dashMatch[3];
    } else if (simpleMatch) {
      sender = simpleMatch[1];
      message = simpleMatch[2];
    }
    
    // Detect Media Attachments
    // Patterns: <Media omitted>, [Image], IMG-2024.jpg, VID-2024.mp4
    const imagePattern = /(IMG-\d+|image|photo|pic|\[image\]|<image>|(\w+\.(jpg|png|jpeg)))/i;
    const videoPattern = /(VID-\d+|video|movie|clip|\[video\]|<video>|(\w+\.(mp4|mov|avi)))/i;

    if (imagePattern.test(message)) {
      const seed = message.replace(/[^a-zA-Z0-9]/g, '').substring(0, 10);
      attachment = { type: 'image', url: `https://picsum.photos/seed/${seed}/800/600` };
    } else if (videoPattern.test(message)) {
      attachment = { type: 'video', url: 'https://www.w3schools.com/html/mov_bbb.mp4' };
    }
    
    messages.push({
      sender: sender.trim(),
      timestamp: timestamp.trim(),
      message: message.trim(),
      attachment
    });
  }
  return messages;
}

function analyzeMessages(messages: any[]) {
  let suspiciousCount = 0;
  let suspiciousTextCount = 0;
  let suspiciousMediaCount = 0;
  let imageCount = 0;
  let videoCount = 0;
  
  const analyzed = messages.map(msg => {
    const text = msg.message.toLowerCase();
    let is_suspicious = false;
    let is_text_suspicious = false;
    let is_media_suspicious = false;
    let suspicion_reason = "";
    let sentiment = "neutral";
    let attachment = msg.attachment;
    
    // Check for suspicious keywords
    const matchedKeyword = SUSPICIOUS_KEYWORDS.find(kw => text.includes(kw));
    if (matchedKeyword) {
      is_suspicious = true;
      is_text_suspicious = true;
      suspicion_reason = `Keyword Match: "${matchedKeyword}" detected in text.`;
    }
    
    // Media Classification
    if (attachment) {
      if (attachment.type === 'image') {
        imageCount++;
        const classification = IMAGE_CLASSIFICATIONS.find(c => text.includes(c.trigger)) || 
                               IMAGE_CLASSIFICATIONS[Math.floor(Math.random() * IMAGE_CLASSIFICATIONS.length)];
        attachment.classification = classification.label;
        attachment.reason = classification.reason;
        attachment.description = classification.description;
        
        // EXIF Anomaly Detection
        if (attachment.exif) {
          const exif = attachment.exif;
          const anomalies = [];
          
          // Check for missing GPS
          if (!exif.gps || Object.keys(exif.gps).length === 0) {
            anomalies.push("Missing GPS Metadata (Potential Scrubbing)");
          }
          
          // Check for suspicious device (e.g., unknown or generic)
          if (!exif.tags?.Make || !exif.tags?.Model) {
            anomalies.push("Missing Device Signature");
          }
          
          // Check for timestamp mismatch (e.g., future date or very old date)
          if (exif.tags?.DateTimeOriginal) {
            const date = new Date(exif.tags.DateTimeOriginal * 1000);
            const now = new Date();
            if (date > now) {
              anomalies.push("Future Timestamp Detected (Potential Clock Manipulation)");
            }
          }

          if (anomalies.length > 0) {
            is_suspicious = true;
            is_media_suspicious = true;
            const exifReason = `EXIF Anomalies: ${anomalies.join(", ")}`;
            suspicion_reason = suspicion_reason ? `${suspicion_reason} | ${exifReason}` : exifReason;
            attachment.exif_anomalies = anomalies;
          }
        }

        if (classification.suspicious) {
          is_suspicious = true;
          is_media_suspicious = true;
          const mediaReason = classification.reason || "Suspicious Image Content";
          suspicion_reason = suspicion_reason ? `${suspicion_reason} | ${mediaReason}` : mediaReason;
        }
      } else if (attachment.type === 'video') {
        videoCount++;
        const finalClass = VIDEO_CLASSIFICATIONS.find(c => text.includes(c.trigger)) || 
                           VIDEO_CLASSIFICATIONS[Math.floor(Math.random() * VIDEO_CLASSIFICATIONS.length)];
        
        attachment.classification = finalClass.label;
        attachment.reason = finalClass.reason;
        attachment.description = finalClass.description;
        if (finalClass.suspicious) {
          is_suspicious = true;
          is_media_suspicious = true;
          const mediaReason = finalClass.reason || "Suspicious Video Content";
          suspicion_reason = suspicion_reason ? `${suspicion_reason} | ${mediaReason}` : mediaReason;
        }
      }
    }

    if (is_suspicious) suspiciousCount++;
    if (is_text_suspicious) suspiciousTextCount++;
    if (is_media_suspicious) suspiciousMediaCount++;
    
    // Sentiment analysis
    if (NEGATIVE_KEYWORDS.some(kw => text.includes(kw))) {
      sentiment = "negative";
    } else if (POSITIVE_KEYWORDS.some(kw => text.includes(kw))) {
      sentiment = "positive";
    }
    
    return { ...msg, sentiment, is_suspicious, is_text_suspicious, is_media_suspicious, suspicion_reason, attachment };
  });
  
  return {
    messages: analyzed,
    summary: {
      total_messages: analyzed.length,
      suspicious_count: suspiciousCount,
      suspicious_text_count: suspiciousTextCount,
      suspicious_media_count: suspiciousMediaCount,
      image_count: imageCount,
      video_count: videoCount,
      score: Math.min(suspiciousCount * 10, 100)
    }
  };
}

async function startServer() {
  const app = express();
  const PORT = 3000;
  const DATA_DIR = path.join(process.cwd(), 'backend', 'data');
  const UPLOADS_DIR = path.join(process.cwd(), 'uploads');
  const PROCESSED_FILE = path.join(DATA_DIR, 'processed.json');

  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  }

  const upload = multer({ 
    dest: 'uploads/',
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
  });

  app.use(express.json());

  // Auth Middleware
  const authenticateToken = (req: any, res: any, next: any) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
      if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
      req.user = user;
      next();
    });
  };

  // Auth Endpoints
  app.post('/api/auth/signup', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    if (users.find(u => u.email === email)) {
      return res.status(400).json({ error: 'User already exists.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser: User = {
      id: Math.random().toString(36).substring(2, 9),
      name,
      email,
      passwordHash
    };

    users.push(newUser);
    res.status(201).json({ message: 'User created successfully.' });
  });

  app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(400).json({ error: 'Invalid email or password.' });
    }

    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid email or password.' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  });

  app.get('/api/auth/me', authenticateToken, (req: any, res) => {
    res.json({ user: req.user });
  });

  // API Endpoints
  app.get('/api/analyze', authenticateToken, (req, res) => {
    if (fs.existsSync(PROCESSED_FILE)) {
      const data = fs.readFileSync(PROCESSED_FILE, 'utf-8');
      res.json(JSON.parse(data));
    } else {
      res.status(404).json({ error: 'No analysis data found.' });
    }
  });

  app.post('/api/upload', authenticateToken, (req, res, next) => {
    upload.single('file')(req, res, (err) => {
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(400).json({ error: 'File too large. Maximum size is 10MB.' });
        }
        return res.status(400).json({ error: `Upload error: ${err.message}` });
      } else if (err) {
        return res.status(500).json({ error: 'Internal server error during upload.' });
      }
      next();
    });
  }, (req: any, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
      
      const fileType = req.file.mimetype;
      const originalName = req.file.originalname.toLowerCase();
      let result;

      if (fileType.startsWith('image/')) {
        // Direct image analysis
        const imageBuffer = fs.readFileSync(req.file.path);
        const base64Image = `data:${fileType};base64,${imageBuffer.toString('base64')}`;
        
        let exifData = null;
        try {
          const parser = ExifParser.create(imageBuffer);
          exifData = parser.parse();
        } catch (e) {
          console.error("EXIF Parsing failed:", e);
        }

        const mockMessage = {
          sender: "System",
          timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
          message: `Direct Forensic Image Scan: ${req.file.originalname}`,
          attachment: { 
            type: 'image', 
            url: base64Image,
            classification: "Manual Forensic Scan",
            reason: "User initiated direct forensic analysis on an extracted image file.",
            description: "This image was directly uploaded for analysis. AI is scanning for metadata, hidden patterns, and illicit content.",
            exif: exifData
          }
        };
        
        result = analyzeMessages([mockMessage]);
      } else if (originalName.endsWith('.zip')) {
        // ZIP file analysis
        const zip = new AdmZip(req.file.path);
        const zipEntries = zip.getEntries();
        const allMessages: any[] = [];
        
        for (const entry of zipEntries) {
          if (entry.isDirectory) continue;
          
          const entryName = entry.entryName.toLowerCase();
          if (entryName.endsWith('.txt')) {
            const content = entry.getData().toString('utf8');
            if (content.trim()) {
              const messages = parseChat(content);
              allMessages.push(...messages);
            }
          } else if (entryName.endsWith('.jpg') || entryName.endsWith('.jpeg') || entryName.endsWith('.png')) {
            const imageBuffer = entry.getData();
            const mimeType = entryName.endsWith('.png') ? 'image/png' : 'image/jpeg';
            const base64Image = `data:${mimeType};base64,${imageBuffer.toString('base64')}`;
            
            let exifData = null;
            try {
              const parser = ExifParser.create(imageBuffer);
              exifData = parser.parse();
            } catch (e) {
              console.error(`EXIF Parsing failed for ${entry.entryName}:`, e);
            }

            allMessages.push({
              sender: "System",
              timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
              message: `Extracted Forensic Image: ${entry.entryName}`,
              attachment: { 
                type: 'image', 
                url: base64Image,
                classification: "Forensic Extraction",
                reason: "Extracted from forensic ZIP archive.",
                description: "This image was extracted from a forensic archive for detailed analysis.",
                exif: exifData
              }
            });
          }
        }
        
        if (allMessages.length === 0) {
          return res.status(400).json({ error: 'No valid forensic evidence found in the ZIP archive. Please include .txt chat logs or image files.' });
        }
        
        result = analyzeMessages(allMessages);
      } else if (originalName.endsWith('.txt')) {
        // Chat log analysis
        const content = fs.readFileSync(req.file.path, 'utf-8');
        
        if (!content.trim()) {
          return res.status(400).json({ error: 'The uploaded file is empty.' });
        }

        const messages = parseChat(content);
        
        if (messages.length === 0) {
          return res.status(400).json({ 
            error: 'Invalid chat log format. Could not extract any messages. Please ensure the file follows the forensic log format: [YYYY-MM-DD HH:MM] Sender: Message' 
          });
        }

        result = analyzeMessages(messages);
      } else {
        return res.status(400).json({ error: 'Unsupported file type. Please upload a .txt chat log or an image file.' });
      }
      
      fs.writeFileSync(PROCESSED_FILE, JSON.stringify(result, null, 2));
      fs.unlinkSync(req.file.path); // Clean up
      
      res.json({ success: true, data: result });
    } catch (error) {
      console.error('Upload error:', error);
      if (req.file && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      res.status(500).json({ error: 'An error occurred while processing the forensic evidence.' });
    }
  });

  // Duplicate route removed

  app.get('/api/report', authenticateToken, (req, res) => {
    if (!fs.existsSync(PROCESSED_FILE)) {
      return res.status(404).json({ error: 'No report found' });
    }
    res.download(PROCESSED_FILE, 'forensic_report.json');
  });

  app.get('/api/report/insight', (req, res) => {
    if (!fs.existsSync(PROCESSED_FILE)) {
      return res.status(404).json({ error: 'No report found' });
    }
    try {
      const data = JSON.parse(fs.readFileSync(PROCESSED_FILE, 'utf-8'));
      
      let report = `SMART MOBILE FORENSIC ANALYZER - INSIGHT REPORT\n`;
      report += `================================================\n`;
      report += `Generated on: ${new Date().toLocaleString()}\n\n`;
      
      report += `EXECUTIVE SUMMARY\n`;
      report += `-----------------\n`;
      report += `Total Messages Analyzed: ${data.summary.total_messages}\n`;
      report += `Suspicious Messages Detected: ${data.summary.suspicious_count}\n`;
      report += `Overall Suspicion Score: ${data.summary.score}/100\n\n`;
      
      if (data.summary.suspicious_count > 0) {
        report += `DETAILED SUSPICIOUS ACTIVITY LOG\n`;
        report += `-------------------------------\n`;
        (data.messages || []).filter((m: any) => m.is_suspicious).forEach((m: any, i: number) => {
          report += `[${i + 1}] TIMESTAMP: ${m.timestamp}\n`;
          report += `    SENDER: ${m.sender}\n`;
          report += `    MESSAGE: "${m.message}"\n`;
          report += `    SENTIMENT: ${m.sentiment.toUpperCase()}\n`;
          report += `    -------------------------------\n`;
        });
      } else {
        report += `No suspicious activities were detected in the analyzed dataset.\n`;
      }
      
      report += `\nEND OF REPORT\n`;
      
      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Content-Disposition', 'attachment; filename=forensic_insight_report.txt');
      res.send(report);
    } catch (error) {
      res.status(500).send('Error generating report');
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
