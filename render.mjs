// node render.mjs <sceneList e.g. 0,1,2>  — renders scenes to parts/s{i}.mp4 (30fps, 1920x1080)
import { chromium } from '/usr/local/lib/node_modules/playwright/index.mjs';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
const ONLY = (process.argv[2] || '').split(',').filter(Boolean).map(Number);
const FPS = 30;
fs.mkdirSync('parts', { recursive: true });
const b = await chromium.launch({ args: ['--use-gl=angle', '--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--disable-web-security'] });
const pg = await b.newPage({ viewport: { width: 1920, height: 1080 } });
pg.on('pageerror', e => console.log('PAGEERR', e.message));
await pg.goto('http://127.0.0.1:8090/stage.html');
await pg.waitForFunction('window.stageReady===true', null, { timeout: 120000 });
await pg.evaluate('window.ready');
const sc = await pg.evaluate('window.SC');
fs.writeFileSync('cues.json', JSON.stringify(await pg.evaluate('cues()')));
const nfr = Math.round(sc[sc.length - 1] * FPS);
const bounds = sc.map(x => Math.round(x * FPS)); bounds[bounds.length - 1] = nfr;
const t0 = Date.now();
for (let i = 0; i < bounds.length - 1; i++) {
  if (ONLY.length && !ONLY.includes(i)) continue;
  const tmp = `parts/s${i}.tmp.mp4`, fn = `parts/s${i}.mp4`;
  const ff = spawn('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'image2pipe', '-framerate', String(FPS), '-c:v', 'mjpeg', '-i', '-', '-c:v', 'libx264', '-crf', '17', '-preset', 'veryfast', '-pix_fmt', 'yuv420p', '-r', String(FPS), tmp], { stdio: ['pipe', 'inherit', 'inherit'] });
  const done = new Promise(r => ff.on('close', r));
  for (let f = bounds[i]; f < bounds[i + 1]; f++) {
    await pg.evaluate(([t, f]) => window.render(t, f), [f / FPS, f]);
    const buf = await pg.screenshot({ type: 'jpeg', quality: 93 });
    if (!ff.stdin.write(buf)) await new Promise(r => ff.stdin.once('drain', r));
  }
  ff.stdin.end(); const code = await done;
  if (code !== 0) { console.log('ffmpeg failed', i); process.exit(1); }
  fs.renameSync(tmp, fn);
  console.log(`scene ${i} frames ${bounds[i + 1] - bounds[i]} t=${Math.round((Date.now() - t0) / 1000)}s`);
}
await b.close();
