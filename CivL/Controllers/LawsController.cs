using System;
using System.Data.Entity;
using System.Linq;
using System.Web.Mvc;

using CivL.DTOs;
using CivL.Models;
using CivL.ViewModels.Laws;
using Microsoft.AspNet.Identity;

namespace CivL.Controllers
{
    [RoutePrefix("Laws")]
    public class LawsController : Controller
    {
        [Route]
        [Route("~")]
        [Route("Index")]
        [HttpGet]
        public ViewResult Index()
        {
            CivLDbContext dbCivL = GetCivLDbContext();

            IndexViewModel viewModel = new IndexViewModel()
            {
                AllLaws = dbCivL.Laws.ToList()
            };

            return View(viewModel);
        }

        [Route("{id}")]
        [HttpGet]
        public ViewResult Law(int id)
        {
            CivLDbContext dbCivL = GetCivLDbContext();

            Law law = dbCivL.Laws.Find(id);

            if (law == null)
            {
                ErrorDTO errorDTO = new ErrorDTO()
                {
                    Message = $"Law {id} does not exist."
                };

                return View("Error", errorDTO);
            }
            else
            {
                return View(law);
            }
        }

        [Route("{id}")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Law(int id, Law law)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return View(law);
                }
                else
                {
                    CivLDbContext dbCivL = GetCivLDbContext();

                    Law existingLaw = dbCivL.Laws.Find(law.ID);

                    if (existingLaw == null)
                    {
                        throw new Exception($"Law {law.ID} does not exist.");
                    }
                    else
                    {
                        existingLaw.Name = law.Name;
                        existingLaw.Text = law.Text;

                        dbCivL.SaveChanges();

                        return RedirectToAction("Index");
                    }
                }
            }
            catch (Exception ex)
            {
                ErrorDTO errorDTO = new ErrorDTO()
                {
                    Message = $"An error occurred while trying to save Law {law.ID}.",
                    MessageDetail = ex.Message
                };

                return View("Error", errorDTO);
            }
        }

        [Route("New")]
        [HttpGet]
        public ViewResult New()
        {
            return View();
        }

        [Route("New")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult New(Law law)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return View(law);
                }
                else
                {
                    CivLDbContext dbCivL = GetCivLDbContext();

                    dbCivL.Laws.Add(law);
                    dbCivL.SaveChanges();

                    return RedirectToAction("Index");
                }
            }
            catch(Exception ex)
            {
                ErrorDTO errorDTO = new ErrorDTO()
                {
                    Message = "An error occurred while creating a new law.",
                    MessageDetail = ex.Message
                };

                return View("Error", errorDTO);
            }
        }

        private CivLDbContext GetCivLDbContext()
        {
            return new CivLDbContext(User.Identity.GetUserId());
        }
    }
}