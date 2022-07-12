# Definition of Done
Below we define the criteria for determining whether an issue or set of issues can be considered as "done."

## Making issues
Before taking on a new issue, it is important to make sure that the issues being made are clear and outline a specific task.  Below are some helpful criteria for what makes a good issue:

1. Issues must include a description stating the problem and providing any necessary context. 
   1. As part of context, it may be helpful to link to design specification documents, PRs, or other issues. 
2. Issues must list criteria for closing e.g:
   1. What functionality/logic must exist for the problem described to be solved or addressed? 
   2. Are there any issues that should be made as a product of this issue? 
   3. What tests need to be written as part of this issue? 
3. Issues must be tagged with the appropriate epic(s).

## Making and Reviewing PRs
Once you, as the developer, have worked on a well-defined issue or set of issues (as described above), you can use the following list of criteria to see if your code is ready for review. The PR reviewer can use the same list for their review as well.

Aside from checking that the general functionality and logic of the code addresses the issue(s) at hand, you and the reviewer should check that:
1. All "checks" pass. This repo's Github actions runs a formatting check (`rustfmt`), a linting check (`clippy`), and runs all unit and integration tests in the repo. It may be helpful, as the developer, to make a draft PR so that Github can run these checks for you instead of having to run them locally. 
2. The code is readable and self-explanatory for the reader, and there are comments where appropriate to provide clarity. 
3. Public APIs are properly documented. (Public can be internal as well. If the API needs to be called from within another program, it needs to be documented as well.)
4. The new code has testing infrastructure - this includes appropriate unit tests and/or integration tests, and issues to describe plans for creating any testing infrastructure that could not be included in the PR. 
5. Any TODOs left in the code are marked with an associated issue number to an issue that is defined using the above criteria.


If you think your code passes the above criteria, you can mark your code/draft PR as ready for review. If the reviewer agrees, they can approve the PR. Once the PR is approved, you can merge your branch, barring any specific merging/branching issues depending on the state of the repo.
































