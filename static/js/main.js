/**
 * main.js - Library Management System Client Script
 * Phase 3: Interactive Modals, Flash Notifications, CSRF Injection & Live Fine Calculation
 */

document.addEventListener('DOMContentLoaded', () => {
  // Mobile Sidebar Toggle
  const mobileMenuBtn = document.getElementById('mobileMenuBtn');
  const sidebar = document.getElementById('sidebar');
  const sidebarOverlay = document.getElementById('sidebarOverlay');

  function openSidebar() {
    if (sidebar && sidebarOverlay) {
      sidebar.classList.add('open');
      sidebarOverlay.classList.add('active');
      document.body.style.overflow = 'hidden';
    }
  }

  function closeSidebar() {
    if (sidebar && sidebarOverlay) {
      sidebar.classList.remove('open');
      sidebarOverlay.classList.remove('active');
      document.body.style.overflow = '';
    }
  }

  if (mobileMenuBtn && sidebar && sidebarOverlay) {
    mobileMenuBtn.addEventListener('click', openSidebar);
    sidebarOverlay.addEventListener('click', closeSidebar);
  }

  // Toast / Flash Notification Dismissal & Auto-Fade
  const alertElements = document.querySelectorAll('.alert');
  alertElements.forEach(alert => {
    // Manual Close
    const closeBtn = alert.querySelector('.alert-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        dismissAlert(alert);
      });
    }

    // Auto-dismiss after 5 seconds (5000ms)
    setTimeout(() => {
      dismissAlert(alert);
    }, 5000);
  });

  function dismissAlert(alert) {
    if (!alert || !alert.parentElement) return;
    alert.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
    alert.style.opacity = '0';
    alert.style.transform = 'translateY(-10px)';
    setTimeout(() => {
      if (alert.parentElement) {
        alert.remove();
      }
    }, 300);
  }

  // Modal Dialog Controllers
  window.openModal = function(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.add('active');
      document.body.style.overflow = 'hidden';
      // Phase 4 Ergonomics: Autofocus on the first input, select, or textarea
      const firstInput = modal.querySelector('input:not([type="hidden"]), select, textarea');
      if (firstInput) {
        setTimeout(() => {
          firstInput.focus();
        }, 60);
      }
    }
  };

  window.closeModal = function(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.remove('active');
      // Only restore scroll if no other modals remain open
      if (!document.querySelector('.modal-backdrop.active')) {
        document.body.style.overflow = '';
      }
    }
  };

  // Close modal when clicking backdrop outside box
  document.querySelectorAll('.modal-backdrop').forEach(modal => {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        window.closeModal(modal.id);
      }
    });
  });

  // Phase 4 Ergonomics: Dismiss active modals with the Escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' || e.keyCode === 27) {
      const activeModal = document.querySelector('.modal-backdrop.active');
      if (activeModal) {
        window.closeModal(activeModal.id);
      }
    }
  });

  // Delegated click handler for declarative modal triggers
  document.addEventListener('click', (e) => {
    const openTrigger = e.target.closest('[data-open-modal]');
    if (openTrigger) {
      e.preventDefault();
      const targetModal = openTrigger.getAttribute('data-open-modal');
      window.openModal(targetModal);
    }

    const closeTrigger = e.target.closest('[data-close-modal]');
    if (closeTrigger) {
      e.preventDefault();
      const targetModal = closeTrigger.getAttribute('data-close-modal');
      window.closeModal(targetModal);
    }
  });

  // Event Delegation for Book Edit & Delete Buttons
  document.addEventListener('click', (e) => {
    const editBookBtn = e.target.closest('.btn-edit-book');
    if (editBookBtn) {
      const id = editBookBtn.getAttribute('data-id');
      const title = editBookBtn.getAttribute('data-title');
      const author = editBookBtn.getAttribute('data-author');
      const category = editBookBtn.getAttribute('data-category');
      const isbn = editBookBtn.getAttribute('data-isbn');
      const copies = editBookBtn.getAttribute('data-copies');

      const form = document.getElementById('editBookForm');
      if (form) {
        form.action = `/books/${id}/edit`;
        document.getElementById('editBookTitle').value = title;
        document.getElementById('editBookAuthor').value = author;
        document.getElementById('editBookCategory').value = category;
        document.getElementById('editBookIsbn').value = isbn;
        document.getElementById('editBookTotalCopies').value = copies;
        window.openModal('editBookModal');
      }
    }

    const deleteBookBtn = e.target.closest('.btn-delete-book');
    if (deleteBookBtn) {
      const id = deleteBookBtn.getAttribute('data-id');
      const title = deleteBookBtn.getAttribute('data-title');

      const form = document.getElementById('deleteBookForm');
      const titleDisplay = document.getElementById('deleteBookTitleDisplay');
      if (form && titleDisplay) {
        form.action = `/books/${id}/delete`;
        titleDisplay.textContent = title;
        window.openModal('deleteBookModal');
      }
    }

    const editMemberBtn = e.target.closest('.btn-edit-member');
    if (editMemberBtn) {
      const id = editMemberBtn.getAttribute('data-id');
      const name = editMemberBtn.getAttribute('data-name');
      const email = editMemberBtn.getAttribute('data-email');
      const phone = editMemberBtn.getAttribute('data-phone');
      const type = editMemberBtn.getAttribute('data-type');
      const status = editMemberBtn.getAttribute('data-status');

      const form = document.getElementById('editMemberForm');
      if (form) {
        form.action = `/members/${id}/edit`;
        document.getElementById('editMemberName').value = name;
        document.getElementById('editMemberEmail').value = email;
        document.getElementById('editMemberPhone').value = phone;
        document.getElementById('editMemberType').value = type;
        document.getElementById('editMemberStatus').value = status;
        window.openModal('editMemberModal');
      }
    }
  });

  // Dynamic Return Fine Calculation
  const loanSelect = document.getElementById('loanSelect');
  const returnDateInput = document.getElementById('returnDate');
  const fineAmountInput = document.getElementById('fineAmount');
  const overdueNote = document.getElementById('overdueNote');
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

  function updateReturnFine() {
    if (!loanSelect || !returnDateInput || !fineAmountInput) return;

    const selectedOption = loanSelect.options[loanSelect.selectedIndex];
    if (!selectedOption || !selectedOption.value) {
      fineAmountInput.value = "$0.00";
      if (overdueNote) overdueNote.textContent = "Select a loan record to calculate fines.";
      return;
    }

    const dueDateStr = selectedOption.getAttribute('data-due-date');
    const returnDateStr = returnDateInput.value;

    if (!dueDateStr || !returnDateStr) return;

    // Attach CSRF header to API calls
    const headers = {};
    if (csrfToken) {
      headers['X-CSRFToken'] = csrfToken;
    }

    fetch(`/api/calculate-fine?due_date=${encodeURIComponent(dueDateStr)}&return_date=${encodeURIComponent(returnDateStr)}`, {
      headers: headers
    })
      .then(response => {
        if (!response.ok) {
          throw new Error('API request failed');
        }
        return response.json();
      })
      .then(data => {
        if (data.fine !== undefined) {
          fineAmountInput.value = `$${parseFloat(data.fine).toFixed(2)}`;
          if (overdueNote) {
            if (data.overdue_days > 0) {
              overdueNote.textContent = `⚠️ Overdue by ${data.overdue_days} day(s) at $${parseFloat(data.rate).toFixed(2)}/day.`;
              overdueNote.style.color = "var(--stat-red)";
            } else {
              overdueNote.textContent = "✓ On schedule. No late fees assessed.";
              overdueNote.style.color = "var(--stat-green)";
            }
          }
        }
      })
      .catch(err => {
        console.error("Error fetching fine calculation:", err);
      });
  }

  if (loanSelect && returnDateInput) {
    loanSelect.addEventListener('change', updateReturnFine);
    returnDateInput.addEventListener('change', updateReturnFine);
    if (loanSelect.value) {
      updateReturnFine();
    }
  }

  // Table instant search
  const globalSearch = document.getElementById('globalSearch');
  if (globalSearch) {
    globalSearch.addEventListener('keyup', (e) => {
      const q = e.target.value.toLowerCase();
      document.querySelectorAll('.data-table tbody tr').forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  }
});
