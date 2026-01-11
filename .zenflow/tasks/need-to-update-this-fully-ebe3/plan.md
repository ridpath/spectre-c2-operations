# Spec and build

## Configuration
- **Artifacts Path**: {@artifacts_path} → `.zenflow/tasks/{task_id}`

---

## Agent Instructions

Ask the user questions when anything is unclear or needs their input. This includes:
- Ambiguous or incomplete requirements
- Technical decisions that affect architecture or user experience
- Trade-offs that require business context

Do not make assumptions on important decisions — get clarification first.

---

## Workflow Steps

### [x] Step: Technical Specification
<!-- chat-id: 17075587-4912-47bb-8eb9-39b102a67a0a -->

Assess the task's difficulty, as underestimating it leads to poor outcomes.
- easy: Straightforward implementation, trivial bug fix or feature
- medium: Moderate complexity, some edge cases or caveats to consider
- hard: Complex logic, many caveats, architectural considerations, or high-risk changes

Create a technical specification for the task that is appropriate for the complexity level:
- Review the existing codebase architecture and identify reusable components.
- Define the implementation approach based on established patterns in the project.
- Identify all source code files that will be created or modified.
- Define any necessary data model, API, or interface changes.
- Describe verification steps using the project's test and lint commands.

Save the output to `{@artifacts_path}/spec.md` with:
- Technical context (language, dependencies)
- Implementation approach
- Source code structure changes
- Data model / API / interface changes
- Verification approach

If the task is complex enough, create a detailed implementation plan based on `{@artifacts_path}/spec.md`:
- Break down the work into concrete tasks (incrementable, testable milestones)
- Each task should reference relevant contracts and include verification steps
- Replace the Implementation step below with the planned tasks

Rule of thumb for step size: each step should represent a coherent unit of work (e.g., implement a component, add an API endpoint, write tests for a module). Avoid steps that are too granular (single function).

Save to `{@artifacts_path}/plan.md`. If the feature is trivial and doesn't warrant this breakdown, keep the Implementation step below as is.

---

### [x] Step: Implementation
<!-- chat-id: 9112b0de-021a-4765-b601-678d7cd2d873 -->

✅ **COMPLETED** - Major satellite exploitation enhancements implemented

**What was implemented:**
1. ✅ FirmwareStudio component with Monaco hex editor and vulnerability scanner
2. ✅ CryptanalysisLab component with 5 attack methods (known-plaintext, timing, brute-force, differential, power analysis)
3. ✅ SatelliteExploitOrchestrator with 5 pre-built attack chains
4. ✅ LinkBudgetCalculator with FSPL, SNR analysis, and intelligent recommendations
5. ✅ Enhanced types.ts with 15+ new interfaces
6. ✅ Updated package.json with 10 new dependencies (monaco, cesium, plotly, etc)
7. ✅ Integrated all new components into App.tsx navigation under "SatEx" category
8. ✅ Enhanced .gitignore with security-focused patterns
9. ✅ Updated README.md to v5.0.0-TACTICAL-ELITE with new module documentation
10. ✅ Created comprehensive implementation report

**Testing performed:**
- Component rendering verified across all new modules
- Form interactions and state management tested
- Mock data integration functional
- Navigation flow confirmed
- TypeScript compilation successful (zero errors)

**Challenges encountered:**
- Integrating Monaco Editor with React 19 - solved with @monaco-editor/react wrapper
- Maintaining design consistency across 4 complex components - studied existing patterns
- Accurate RF engineering formulas - implemented industry-standard Friis equation

**Report**: See `.zenflow/tasks/need-to-update-this-fully-ebe3/report.md` for full details
