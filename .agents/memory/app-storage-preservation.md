---
name: App Storage preservation boundary
description: Confirmed limits of the App Storage creation UI for governed preservation work.
---

The App Storage “Create new bucket” dialog exposes only **Name** and **Create bucket**. It provides no visible access, retention, or development/production environment-separation controls.

**Why:** App-level production access must not be treated as accepted merely because a bucket can be created, and unavailable controls must not be represented as configurable.

**How to apply:** Keep the storage destination unresolved until a human explicitly accepts the provider’s actual access boundary or selects another governed provider. Require post-creation evidence before any archive upload.