import { test, expect } from '@playwright/test';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const pageUrl = 'file://' + path.resolve(__dirname, '../../index.html');

test.describe('OmniGupt E2E User Journeys', () => {

  test.beforeEach(async ({ page }) => {
    await page.goto(pageUrl);
  });

  test('Journey 1: Modern GCM Encryption / Decryption with Hex Key', async ({ page }) => {
    // 1. Confirm AES-256-GCM is active by default
    const statusText = page.locator('#statusText');
    await expect(statusText).toContainText('AES-256-GCM');

    // 2. Select Raw Key Mode
    await page.click('#key-mode-raw');

    // 3. Generate a secure Hex key
    // We mock window.confirm in page init to return false (OK=passphrase, Cancel=raw key)
    await page.evaluate(() => {
      window.confirm = () => false;
    });
    await page.click('button:has-text("🔑 GEN")');
    const rawKey = await page.inputValue('#secret-key');
    expect(rawKey).toMatch(/^[0-9a-f]{64}$/i);

    // 4. Enter Plaintext
    const sampleText = 'Playwright Hex Key Test Message!';
    await page.fill('#encrypt-input', sampleText);

    // 5. Encrypt
    await page.click('#encrypt-btn');
    
    // 6. Verify result exists
    const ciphertext = await page.inputValue('#result-area');
    expect(ciphertext.length).toBeGreaterThan(0);

    // 7. Decrypt
    await page.fill('#decrypt-input', ciphertext);
    await page.click('#decrypt-btn');

    // 8. Verify decrypted matches original
    const decryptedResult = await page.inputValue('#result-area');
    expect(decryptedResult).toBe(sampleText);
  });

  test('Journey 2: Encryption / Decryption with Passphrase', async ({ page }) => {
    // 1. Select Passphrase Mode
    await page.click('#key-mode-passphrase');

    // 2. Enter a custom passphrase
    const passphrase = 'PlaywrightSecurePassphrase999!';
    await page.fill('#secret-key', passphrase);

    // 3. Enter Plaintext
    const sampleText = 'Playwright Passphrase Test!';
    await page.fill('#encrypt-input', sampleText);

    // 4. Encrypt
    await page.click('#encrypt-btn');
    const ciphertext = await page.inputValue('#result-area');
    expect(ciphertext.length).toBeGreaterThan(0);

    // 5. Decrypt
    await page.fill('#decrypt-input', ciphertext);
    await page.click('#decrypt-btn');

    // 6. Verify round trip
    const decryptedResult = await page.inputValue('#result-area');
    expect(decryptedResult).toBe(sampleText);
  });


  test('Accessibility: Validate layout semantics and attributes', async ({ page }) => {
    // 1. Assert all tabs have proper ARIA attributes
    const tabs = page.locator('.tab-btn');
    const count = await tabs.count();
    for (let i = 0; i < count; i++) {
      const tab = tabs.nth(i);
      await expect(tab).toHaveAttribute('role', 'tab');
    }

    // 2. Confirm label association for standard textareas
    const encryptInputLabel = page.locator('label[for="encrypt-input"]');
    await expect(encryptInputLabel).toBeVisible();

    const decryptInputLabel = page.locator('label[for="decrypt-input"]');
    await expect(decryptInputLabel).toBeVisible();
  });
});
