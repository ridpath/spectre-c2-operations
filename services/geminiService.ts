
import { GoogleGenAI } from "@google/genai";

// Always use fresh instances of GoogleGenAI within service calls to ensure process.env.API_KEY is current

export const analyzeCommandOutput = async (command: string, output: string) => {
  try {
    const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
    const response = await ai.models.generateContent({
      model: 'gemini-3-pro-preview',
      contents: `You are the core intelligence engine for Spectre C2, an advanced post-exploitation framework. 
      Analyze this telemetry from a remote asset:
      
      TACTICAL TASK: ${command}
      RAW TELEMETRY: 
      ${output}
      
      Provide:
      1. Technical analysis of misconfigurations, domain structures, or high-value targets.
      2. Specific Spectre/Pivot commands to further engagement.
      3. Technical, concise, professional tone.`,
    });
    return response.text || "No analysis available.";
  } catch (error) {
    console.error("Gemini analysis failed:", error);
    return "Intelligence engine timeout. Ensure signal bridge is active.";
  }
};

export const suggestNextSteps = async (history: string[]) => {
  try {
    const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
    const response = await ai.models.generateContent({
      model: 'gemini-3-flash-preview',
      contents: `Based on this Spectre C2 operational history:
      ${history.join('\n')}
      
      Suggest the 3 most effective tactical next steps for infiltration or lateral movement.`,
    });
    return response.text || "No suggestions found.";
  } catch (error) {
    console.error("Gemini suggestions failed:", error);
    return "Unable to predict next tactical steps.";
  }
};

export const generateDropper = async (targetEnv: string, lhost: string, lport: string) => {
  try {
    const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
    const response = await ai.models.generateContent({
      model: 'gemini-3-pro-preview',
      contents: `Synthesize a specialized Spectre-Agent stager for a ${targetEnv} machine.
      Signal Core: ${lhost}:${lport}
      
      Include memory patching for detection evasion and stager logic for the next stage.
      
      Return ONLY the code block.`,
    });
    return response.text || "Agent synthesis returned no content.";
  } catch (error) {
    console.error("Payload synthesis failed:", error);
    return "Payload synthesis failed. Utilize default factory templates.";
  }
};
