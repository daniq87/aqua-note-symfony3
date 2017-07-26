<?php

namespace AppBundle\Security;

use AppBundle\Form\LoginForm;
use Doctrine\ORM\EntityManager;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoder;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\Authenticator\AbstractFormLoginAuthenticator;

class LoginFormAuthenticator extends AbstractFormLoginAuthenticator
{
    private $formFactory;
    private $em;
    private $router;
    private $passwordEncoder;

    public function __construct(FormFactoryInterface $formFactory,
                                EntityManager $em,
                                RouterInterface $router,
                                UserPasswordEncoder $passwordEncoder)
    {
        $this->formFactory = $formFactory;
        $this->em = $em;
        $this->router = $router;
        $this->passwordEncoder = $passwordEncoder;
    }

    /**
     * A este metodo se le llama por cada Request.
     * If the URL is '/login' and the HTTP method is POST, our authenticator should spring into action.
     * Otherwise, it should do nothing: this is just a normal page.
     * If you return any non-null value, authentication continues to the next step( call getUser(...) method).
     * @param Request $request
     * @return mixed|void
     */
    public function getCredentials(Request $request)
    {
        $isLoginSubmit = $request->getPathInfo() == '/login' && $request->isMethod('POST');
        if (!$isLoginSubmit) {
            // skip authentication
            return;
        }

        $form = $this->formFactory->create(LoginForm::class);
        $form->handleRequest($request);

        $data = $form->getData();
        $request->getSession()->set(
            Security::LAST_USERNAME,
            $data['_username']
        );

        return $data;
    }

    /**
     * If this returns null, guard authentication will fail and the user will see an error.
     * Otherwise we do return a User object, Guard calls checkCredentials()
     * @param mixed $credentials . Equal to what we return in getCredentials()
     * @param UserProviderInterface $userProvider
     * @return \AppBundle\Entity\User
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $username = $credentials['_username'];

        return $this->em->getRepository('AppBundle:User')
            ->findOneBy(['email' => $username]);
    }

    /**
     * verify the user's password if they have one or do any other last-second validation.
     * Return true if you're happy and the user should be logged in.
     * @param mixed $credentials
     * @param UserInterface $user
     * @return bool
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        $password = $credentials['_password'];

        if ($this->passwordEncoder->isPasswordValid($user, $password)) {
            return true;
        }

        return false;
    }

    /**
     * If authentication fails, we redirect to the login form
     * @return mixed
     */
    protected function getLoginUrl()
    {
        return $this->router->generate('security_login');
    }

    /**
     * It is called when authentication is successful.
     * The user is automatically redirected back to the last page they tried to visit before being forced to login
     * @return mixed
     */
    protected function getDefaultSuccessRedirectUrl()
    {
        return $this->router->generate('homepage');
    }
}
