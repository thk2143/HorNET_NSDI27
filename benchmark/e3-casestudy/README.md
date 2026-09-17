# E3 — a verification session

One property is not how verification is used. A campaign is: an engineer takes
an open-source network function and works through a list of functional
questions about it, in order, with the input world — the packet assumptions and
the map contents — held fixed across the whole list.

Four network functions, five properties each. `campaign.py` states the
campaigns — the world, the questions and the verdict each one expects —
and `specs/` holds the specifications, one per property.

```bash
venv/bin/python benchmark/e3-casestudy/run.py
venv/bin/python benchmark/e3-casestudy/run.py --only katran
venv/bin/python benchmark/e3-casestudy/run.py --json out.json
```

What a campaign costs splits in two, and the runner reports both: the program
is tracked once and the verification chain built once (**one-time**), and each
property then costs a spec parse and a solve against that chain (**per
property**). The runner also checks every verdict against the one the campaign
predicts — three of the twenty properties are expected to be `violated`, since
questions an engineer writes and the program refuses are part of a session.
