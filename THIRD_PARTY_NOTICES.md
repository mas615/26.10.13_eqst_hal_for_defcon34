# Third-party material

Challenge metadata, player attachments, and the upstream images referenced as
`llmctf/*` originate from NYU CTF Bench and the original CSAW CTF challenges:

- https://github.com/NYU-LLM-CTF/NYU_CTF_Bench
- Source snapshot used by this project: `4c5744f55a31a58e03d6118c9dbb1c18e5bbdfa9`
- Upstream source for challenge assets is available in that repository's
  `development/` and `test/` trees at the recorded commit.

The upstream repository includes GNU GPL version 2 in its root LICENSE.
That license is reproduced verbatim in [licenses/NYU_CTF_Bench-LICENSE](licenses/NYU_CTF_Bench-LICENSE).
Individual challenges and bundled dependencies may contain additional notices;
those original notices in the player archives are retained.

The Home-specific Orange and OrangeV2 proxy copies in `deployments/` were
modified on 2026-07-30 to handle request errors without terminating the process.
Their Dockerfiles derive from the corresponding upstream images. The original
source is available at the source snapshot above.

This notice preserves attribution for third-party material and does not assign
a new blanket license to the separately developed portal.
