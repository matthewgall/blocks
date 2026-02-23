# Templates

Templates are organized by intent to keep things easy to find.

## Structure

- `internal/templates/views/` - full page templates (lists, detail views, pages)
- `internal/templates/forms/` - form pages (create/edit screens)
- `internal/templates/fragments/` - shared partials and client-side UI fragments

## Notes

- `layout.html` and shared fragments live under `fragments/` and are parsed into every page template.
- Handlers still refer to template names without paths (e.g. `sets.html`, `set_form.html`).
- Add new full pages to `views/` and new form pages to `forms/`.
