import sharp from 'sharp';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Create a simple icon with "POS" text
async function generateIcon(size) {
  const svg = `
    <svg width="${size}" height="${size}" xmlns="http://www.w3.org/2000/svg">
      <rect width="${size}" height="${size}" fill="#10b981" rx="${size * 0.1}"/>
      <text 
        x="50%" 
        y="50%" 
        text-anchor="middle" 
        dy=".35em" 
        fill="white" 
        font-family="Arial, sans-serif" 
        font-size="${size * 0.3}px" 
        font-weight="bold"
      >
        POS
      </text>
    </svg>
  `;

  const buffer = Buffer.from(svg);
  const outputPath = path.join(__dirname, 'public', `pwa-${size}x${size}.png`);
  
  await sharp(buffer)
    .png()
    .toFile(outputPath);
    
  console.log(`Generated ${outputPath}`);
}

// Generate icons
Promise.all([
  generateIcon(192),
  generateIcon(512)
]).then(() => {
  console.log('All icons generated successfully!');
}).catch(err => {
  console.error('Error generating icons:', err);
});