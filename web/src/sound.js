// --- SOUND CUES ---
// Short synthesised tones for send / receive / seen. Deliberately generated
// with WebAudio rather than shipped as audio files: three more assets to
// precache and version, for something that is two sine waves.
//
// The AudioContext is created lazily on the first cue, because browsers
// refuse to start one before a user gesture.

import { State } from './store.js';

let ctx = null;

function context() {
  if (ctx) return ctx;
  const AC = window.AudioContext || window.webkitAudioContext;
  if (!AC) return null;
  try { ctx = new AC(); } catch { return null; }
  return ctx;
}

/**
 * One short enveloped tone.
 * The gain ramp matters: a raw start/stop on an oscillator clicks audibly.
 */
function tone({ freq, start = 0, dur = 0.12, type = 'sine', peak = 1 }) {
  const ac = context();
  if (!ac) return;

  const t0 = ac.currentTime + start;
  const osc = ac.createOscillator();
  const gain = ac.createGain();

  osc.type = type;
  osc.frequency.setValueAtTime(freq, t0);

  const volume = Math.max(0, Math.min(1, State.settings.soundVolume ?? 0.4)) * 0.22 * peak;
  gain.gain.setValueAtTime(0.0001, t0);
  gain.gain.exponentialRampToValueAtTime(Math.max(volume, 0.0002), t0 + 0.012);
  gain.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);

  osc.connect(gain).connect(ac.destination);
  osc.start(t0);
  osc.stop(t0 + dur + 0.02);
}

const CUES = {
  // Rising two-note blip.
  send:    () => { tone({ freq: 660, dur: 0.09 }); tone({ freq: 880, start: 0.07, dur: 0.11 }); },
  // Falling, softer, so an inbound message is distinguishable without looking.
  receive: () => { tone({ freq: 830, dur: 0.10 }); tone({ freq: 620, start: 0.09, dur: 0.14 }); },
  // A single high tick for "they saw it".
  seen:    () => { tone({ freq: 1180, dur: 0.07, peak: 0.55 }); }
};

/** Plays a named cue, if sounds are enabled. Never throws. */
export function playCue(name) {
  if (!State.settings.soundEnabled) return;
  const cue = CUES[name];
  if (!cue) return;
  try {
    const ac = context();
    if (ac && ac.state === 'suspended') ac.resume();
    cue();
  } catch {
    /* audio is a nicety, so never let it break a send */
  }
}

/** Plays a cue regardless of the setting, for previewing it in Settings. */
export function previewCue(name) {
  const was = State.settings.soundEnabled;
  State.settings.soundEnabled = true;
  playCue(name);
  State.settings.soundEnabled = was;
}
