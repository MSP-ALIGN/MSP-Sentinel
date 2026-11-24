<?php
/** Inline validation message under a form field. Expects: $errors (array), $field (string). */
if (!empty($errors[$field])): ?>
<div class="invalid-feedback d-block"><?= e($errors[$field]) ?></div>
<?php endif; ?>
