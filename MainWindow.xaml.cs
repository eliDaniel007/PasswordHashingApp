/*
 * Projet: Application de Hachage de Mots de Passe
 * Auteurs: Oumar Diogo Bah et Eli Daniel Senyo
 * Description: Classe principale gérant la recherche de mots de passe
 *              correspondant à un hash MD5 dans un dictionnaire
 */

using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace PasswordHashingApp
{
    public partial class MainWindow : Window
    {
        // Variables membres pour suivre la progression
        private long totalAttempts = 0;        // Nombre total de tentatives effectuées
        private long totalWords = 0;           // Nombre total de mots dans le dictionnaire
        private Stopwatch timer;               // Chronomètre pour mesurer le temps écoulé
        private DispatcherTimer updateTimer;   // Timer pour les mises à jour de l'interface
        private bool isRunning = false;        // État du processus de hachage

        // Constructeur
        public MainWindow()
        {
            InitializeComponent();
            timer = new Stopwatch();

            // Configuration du timer de mise à jour de l'interface
            updateTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(100)
            };
            updateTimer.Tick += UpdateTimer_Tick;
        }

        /// <summary>
        /// Met à jour l'affichage du temps écoulé et du nombre de tentatives
        /// </summary>
        private void UpdateTimer_Tick(object sender, EventArgs e)
        {
            if (timer.IsRunning)
            {
                ElapsedTimeTextBlock.Text = timer.Elapsed.ToString(@"hh\:mm\:ss");
                AttemptCountTextBlock.Text = totalAttempts.ToString("N0");
            }
        }

        /// <summary>
        /// Gestionnaire du bouton Parcourir pour sélectionner le fichier dictionnaire
        /// </summary>
        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog
            {
                Filter = "Fichiers texte (*.txt)|*.txt|Tous les fichiers (*.*)|*.*",
                DefaultExt = ".txt"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                DictionaryPathTextBox.Text = openFileDialog.FileName;
                CountDictionaryWords();
            }
        }

        /// <summary>
        /// Compte le nombre de mots dans le dictionnaire sélectionné
        /// </summary>
        private void CountDictionaryWords()
        {
            try
            {
                totalWords = File.ReadAllLines(DictionaryPathTextBox.Text).Length;
                DictionaryWordCountTextBlock.Text = totalWords.ToString("N0");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Erreur lors de la lecture du dictionnaire: {ex.Message}", "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Gestionnaire du bouton Valider pour lancer/arrêter la recherche
        /// </summary>
        private async void ValidateButton_Click(object sender, RoutedEventArgs e)
        {
            if (isRunning)
            {
                isRunning = false;
                ValidateButton.Content = "Valider !";
                return;
            }

            if (!ValidateInputs()) return;

            isRunning = true;
            ValidateButton.Content = "Arrêter";
            SetControlsEnabled(false);
            ResetCounters();

            try
            {
                await StartHashingProcess();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Erreur lors du processus de hachage: {ex.Message}", "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                isRunning = false;
                ValidateButton.Content = "Valider !";
                SetControlsEnabled(true);
                updateTimer.Stop();
            }
        }

        /// <summary>
        /// Valide les entrées utilisateur avant de démarrer la recherche
        /// </summary>
        private bool ValidateInputs()
        {
            if (string.IsNullOrWhiteSpace(HashInputTextBox.Text))
            {
                MessageBox.Show("Veuillez entrer un hachage MD5 à rechercher.", "Erreur de validation");
                return false;
            }

            if (string.IsNullOrWhiteSpace(DictionaryPathTextBox.Text) || !File.Exists(DictionaryPathTextBox.Text))
            {
                MessageBox.Show("Veuillez sélectionner un fichier de dictionnaire valide.", "Erreur de validation");
                return false;
            }

            return true;
        }

        /// <summary>
        /// Active/désactive les contrôles de l'interface pendant la recherche
        /// </summary>
        private void SetControlsEnabled(bool enabled)
        {
            DictionaryPathTextBox.IsEnabled = enabled;
            BrowseButton.IsEnabled = enabled;
            HashInputTextBox.IsEnabled = enabled;
        }

        /// <summary>
        /// Réinitialise les compteurs et l'affichage
        /// </summary>
        private void ResetCounters()
        {
            totalAttempts = 0;
            ProgressBar.Value = 0;
            AttemptCountTextBlock.Text = "0";
            ElapsedTimeTextBlock.Text = "00:00:00";
            LogTextBox.Clear();
        }

        /// <summary>
        /// Processus principal de recherche du hash dans le dictionnaire
        /// </summary>
        private async Task StartHashingProcess()
        {
            timer.Restart();
            updateTimer.Start();

            string targetHashString = HashInputTextBox.Text.ToLower();
            LogTextBox.AppendText($"Recherche du hash : {targetHashString}\n");

            // Conversion du hash cible en bytes pour optimiser la comparaison
            byte[] targetHashBytes = new byte[targetHashString.Length / 2];
            for (int i = 0; i < targetHashString.Length; i += 2)
            {
                targetHashBytes[i / 2] = Convert.ToByte(targetHashString.Substring(i, 2), 16);
            }

            using (var md5 = MD5.Create())
            using (var reader = new StreamReader(DictionaryPathTextBox.Text, Encoding.UTF8, false, 8192))
            {
                string line;
                int updateCounter = 0;

                while ((line = await reader.ReadLineAsync()) != null && isRunning)
                {
                    // Calcul du hash MD5 pour chaque mot
                    byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(line));
                    totalAttempts++;

                    // Comparaison optimisée des bytes
                    bool match = true;
                    for (int i = 0; i < hash.Length; i++)
                    {
                        if (hash[i] != targetHashBytes[i])
                        {
                            match = false;
                            break;
                        }
                    }

                    if (match)
                    {
                        timer.Stop();
                        updateTimer.Stop();
                        ShowSuccessMessage(line, targetHashString);
                        return;
                    }

                    // Mise à jour périodique de l'interface
                    updateCounter++;
                    if (updateCounter >= 50000)
                    {
                        updateCounter = 0;
                        ProgressBar.Value = (double)totalAttempts / totalWords * 100;
                        await Task.Yield();
                    }
                }
            }

            if (isRunning)
            {
                timer.Stop();
                updateTimer.Stop();
                MessageBox.Show("Aucune correspondance trouvée dans le dictionnaire.", "Recherche terminée", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        /// <summary>
        /// Affiche le message de succès avec le mot de passe trouvé
        /// </summary>
        private void ShowSuccessMessage(string password, string hash)
        {
            var message = $"Votre hachage :\n{hash}\n\nCorrespond au mot suivant :\n{password}";
            MessageBox.Show(message, "Congratulations!!!", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}