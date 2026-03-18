#!/usr/bin/env php
<?php

require __DIR__ . '/../vendor/autoload.php';

use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Sigstore\Verifier;

class SignBundleCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->setName('sign-bundle')
            ->setDescription('Signs an artifact and outputs a Sigstore bundle.')
            ->addArgument('file', InputArgument::REQUIRED, 'The artifact to sign')
            ->addOption('staging', null, InputOption::VALUE_NONE, 'Use the staging Sigstore environment')
            ->addOption('identity-token', null, InputOption::VALUE_REQUIRED, 'The OIDC identity token')
            ->addOption('bundle', null, InputOption::VALUE_REQUIRED, 'Path to output the Sigstore bundle')
            ->addOption('in-toto', null, InputOption::VALUE_NONE, 'Whether the input is an in-toto attestation')
            ->addOption('trusted-root', null, InputOption::VALUE_REQUIRED, 'Path to the trusted root JSON file')
            ->addOption('signing-config', null, InputOption::VALUE_REQUIRED, 'Path to the signing config JSON file');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $output->writeln('<info>sign-bundle command stub</info>');
        $output->writeln('File: ' . $input->getArgument('file'));
        $output->writeln('Identity Token: ' . $input->getOption('identity-token'));
        $output->writeln('Bundle Output: ' . $input->getOption('bundle'));
        $output->writeln('Staging: ' . ($input->getOption('staging') ? 'yes' : 'no'));
        $output->writeln('In-Toto: ' . ($input->getOption('in-toto') ? 'yes' : 'no'));
        $output->writeln('Trusted Root: ' . $input->getOption('trusted-root'));
        $output->writeln('Signing Config: ' . $input->getOption('signing-config'));

        // TODO: Implement signing logic

        return Command::SUCCESS;
    }
}

class VerifyBundleCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->setName('verify-bundle')
            ->setDescription('Verifies an artifact against a Sigstore bundle.')
            ->addArgument('file_or_digest', InputArgument::REQUIRED, 'The artifact file or sha256:digest to verify')
            ->addOption('staging', null, InputOption::VALUE_NONE, 'Use the staging Sigstore environment')
            ->addOption('bundle', null, InputOption::VALUE_REQUIRED, 'Path to the Sigstore bundle file')
            ->addOption('certificate-identity', null, InputOption::VALUE_REQUIRED, 'The expected certificate identity (e.g., email)')
            ->addOption('certificate-oidc-issuer', null, InputOption::VALUE_REQUIRED, 'The expected OIDC issuer URL')
            ->addOption('key', null, InputOption::VALUE_REQUIRED, 'Path to a PEM-encoded public key for verification')
            ->addOption('trusted-root', null, InputOption::VALUE_REQUIRED, 'Path to the trusted root JSON file');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $output->writeln('<info>verify-bundle command stub</info>');
        $output->writeln('File/Digest: ' . $input->getArgument('file_or_digest'));
        $output->writeln('Bundle: ' . $input->getOption('bundle'));
        $output->writeln('Staging: ' . ($input->getOption('staging') ? 'yes' : 'no'));
        $output->writeln('Cert Identity: ' . $input->getOption('certificate-identity'));
        $output->writeln('Cert Issuer: ' . $input->getOption('certificate-oidc-issuer'));
        $output->writeln('Key: ' . $input->getOption('key'));
        $output->writeln('Trusted Root: ' . $input->getOption('trusted-root'));

        if (($input->getOption('certificate-identity') || $input->getOption('certificate-oidc-issuer')) && $input->getOption('key')) {
            $output->writeln('<error>Cannot use both certificate identity/issuer and key options.</error>');
            return Command::INVALID;
        }
        if (!($input->getOption('certificate-identity') && $input->getOption('certificate-oidc-issuer')) && !$input->getOption('key')) {
             $output->writeln('<error>Must provide either certificate identity/issuer or a key.</error>');
             return Command::INVALID;
        }
                $verifier = new \Sigstore\Verifier();

        try {
            if ($input->getOption('bundle')) {
                $bundle = $verifier->loadBundle($input->getOption('bundle'));
                $output->writeln('<info>Bundle loaded successfully.</info>');
                // TODO: Use the bundle
            }

            if ($input->getOption('trusted-root')) {
                $trustedRoot = $verifier->loadTrustedRoot($input->getOption('trusted-root'));
                $output->writeln('<info>Trusted root loaded successfully.</info>');
                // TODO: Use the trusted root
            }
        } catch (\Exception $e) {
            $output->writeln('<error>Error loading inputs: ' . $e->getMessage() . '</error>');
            return Command::FAILURE;
        }

        // TODO: Implement full verification logic

        return Command::SUCCESS;
    }
}

$application = new Application('Sigstore Conformance CLI', '0.1.0');
$application->add(new SignBundleCommand());
$application->add(new VerifyBundleCommand());
$application->run();
