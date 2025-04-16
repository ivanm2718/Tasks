1. pull changes from git :

git reset --hard
git fetch origin
git reset --hard origin/main


2. edit frontend:

+ Login/Register Forms added
currentView controls visible view (login/register/tasks)
Forms tied to loginForm / registerForm models
Buttons to switch between forms
Feedback via authError & authSuccess

+ Token-Based Auth
JWT stored in localStorage after login
Auto-decoded with decodeToken() → sets currentUser (username, userId, isAdmin)
checkForToken() runs on app init → restores session if valid
authHeaders() → central place for Authorization header when calling API

+ Session-Aware Behavior
All task CRUD functions now use authHeaders (no more hardcoded user_id)
On 401/403 response → auto-logout with error message
isLoggedIn + token gate access to tasks
Logout clears token, tasks, form states

+ Admin visibility
If currentUser.isAdmin, show user info (task owner user_id) next to task
✏️ UX/UI Feedback
Loading states used in login/register/tasks
Disabled buttons while loading
Escape key to cancel task update still works